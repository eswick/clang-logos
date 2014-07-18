//===---- CGLogos.cpp - Emit LLVM Code for ObjC-Logos ---------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This contains code to emit ObjC-Logos code as LLVM code.
//
//===----------------------------------------------------------------------===//



#include "CodeGenFunction.h"
#include "CGObjCRuntime.h"
#include "llvm/Support/CallSite.h"

using namespace clang;
using namespace CodeGen;

/// Create a mangled logos name for a hooked method
///
/// <prefix>$<class>$<selector>
///
/// Semicolons (:) in selector are replaced with '$'
static void GetMangledNameForLogosMethod(std::string prefix, const ObjCMethodDecl *D, SmallVectorImpl<char> &Name) {
    llvm::raw_svector_ostream OS(Name);
    
    std::string sel = D->getSelector().getAsString();
    
    std::replace(sel.begin(), sel.end(), ':', '$');
    
    
    OS << prefix << "$" << D->getClassInterface()->getName() << "$" << sel;
    
}

static unsigned CalculateAssociationPolicy(ObjCPropertyDecl *D) {
  unsigned baseValue;
  
  switch (D->getSetterKind()) {
    case ObjCPropertyDecl::Assign:
      if (!D->getType()->isObjCRetainableType()) {
        // This type is being wrapped in NSValue; retain it
        return 1;
      }
      return 0;
    case ObjCPropertyDecl::Retain:
      baseValue = 1;
      break;
    case ObjCPropertyDecl::Copy:
      baseValue = 3;
      break;
    default:
      assert(false && "Setter kind not supported");
      return 0;
  }
  
  if (D->getPropertyAttributes() & ObjCPropertyDecl::OBJC_PR_nonatomic) {
    baseValue += 01400;
  }
  
  return baseValue;
}


/// Generate a Logos hook method
///
/// This method takes an ObjCMethodDecl and emits it as
/// a normal, C-like function

void CodeGenFunction::GenerateLogosMethodHook(const ObjCMethodDecl *OMD, ObjCHookDecl *Hook) {
    
    // Generate function pointer for @orig
    SmallString <256> OrigName;
    GetMangledNameForLogosMethod("logos_orig", OMD, OrigName);
    
    llvm::GlobalVariable *Orig;
    
    Orig = new llvm::GlobalVariable(
      CGM.getModule(),
      Int8PtrTy,
      false,
      llvm::GlobalValue::InternalLinkage,
      CGM.EmitNullConstant(getContext().VoidPtrTy),
      OrigName.str());
      
    Hook->RegisterOrigPointer(OMD, Orig);
      
      
    // Generate function
    
    SmallString<256> Name;
    GetMangledNameForLogosMethod("logos_method", OMD, Name);
    
    // Set up LLVM types
    CodeGenTypes &Types = getTypes();
    
    llvm::FunctionType *MethodTy = Types.GetFunctionType(Types.arrangeObjCMethodDeclaration(OMD));
    llvm::Function *Fn = llvm::Function::Create(MethodTy, llvm::GlobalValue::InternalLinkage, Name.str(), &CGM.getModule());
    
    const CGFunctionInfo &FI = Types.arrangeObjCMethodDeclaration(OMD);
    CGM.SetInternalFunctionAttributes(OMD, Fn, FI);
    
    
    // Create function args (self, _cmd, ...)
    FunctionArgList args;
    args.push_back(OMD->getSelfDecl());
    args.push_back(OMD->getCmdDecl());
    
    for (ObjCMethodDecl::param_const_iterator PI = OMD->param_begin(),
         E = OMD->param_end(); PI != E; ++PI)
    args.push_back(*PI);
    
    // Emit method
    
    CurGD = OMD;
    
    StartFunction(OMD, OMD->getResultType(), Fn, FI, args, OMD->getLocStart());
    EmitStmt(OMD->getBody());
    FinishFunction(OMD->getBodyRBrace());
    
    Hook->RegisterMethodDefinition(OMD, Fn);
    
}

/// \brief Creates a unique static variable for each property impl to be used
/// as a key for objc_(get/set)AssociatedObject
llvm::GlobalVariable* CodeGenFunction::GetPropertyKey(ObjCHookDecl *Hook,
                                              const ObjCPropertyImplDecl *PID) {
  
  if (llvm::GlobalVariable *Key = Hook->GetPropertyKey(PID))
    return Key;

  SmallString <256> KeyName;
  GetMangledNameForLogosMethod("logos_key", PID->getPropertyDecl()->
                                              getGetterMethodDecl(), KeyName);
                                              
  llvm::GlobalVariable *Key;
  
  Key = new llvm::GlobalVariable(
    CGM.getModule(),
    Int8PtrTy,
    false,
    llvm::GlobalValue::InternalLinkage,
    CGM.EmitNullConstant(getContext().VoidPtrTy),
    KeyName.str());
    
  Hook->RegisterPropertyKey(PID, Key);
  
  return Key;
}

/// \brief Generates a property getter by using Objective-C associated objects 
void CodeGenFunction::GenerateObjCGetter(ObjCHookDecl *Hook,
                                         const ObjCPropertyImplDecl *PID) {
    ObjCMethodDecl *OMD = PID->getPropertyDecl()->getGetterMethodDecl();
    
    // Get static key for property
    llvm::GlobalVariable* Key = GetPropertyKey(Hook, PID);
    
    // Generate function start
    
    SmallString <256> SymbolName;
    GetMangledNameForLogosMethod("logos_method", OMD, SymbolName);
    
    CodeGenTypes &Types = getTypes();
    
    llvm::FunctionType *MethodTy = Types.GetFunctionType(
                                       Types.arrangeObjCMethodDeclaration(OMD));
    llvm::Function *Fn = llvm::Function::Create(MethodTy, 
                                             llvm::GlobalValue::InternalLinkage, 
                                             SymbolName.str(), 
                                             &CGM.getModule());
    
    const CGFunctionInfo &FI = Types.arrangeObjCMethodDeclaration(OMD);
    CGM.SetInternalFunctionAttributes(OMD, Fn, FI);
    
    // Create function args (self, _cmd)
    FunctionArgList args;
    args.push_back(OMD->getSelfDecl());
    args.push_back(OMD->getCmdDecl());
    
    CurGD = OMD;
    
    StartFunction(OMD, OMD->getResultType(), Fn, FI, args, PID->getLocStart());
    
    // Generate body
    
    // id objc_getAssociatedObject(id object, void *key)
    llvm::Type *objc_getAssociatedObjectTypes[] = { Int8PtrTy, Int8PtrTy };
    llvm::FunctionType *objc_getAssociatedObjectType = llvm::FunctionType::get(
                                                  Int8PtrTy, 
                                                  objc_getAssociatedObjectTypes, 
                                                  false);
      
    llvm::Constant *objc_getAssociatedObjectFn = CGM.CreateRuntimeFunction(
                                                  objc_getAssociatedObjectType, 
                                                  "objc_getAssociatedObject");
      
    if (llvm::Function *f = 
                         dyn_cast<llvm::Function>(objc_getAssociatedObjectFn)) {
        f->setLinkage(llvm::Function::ExternalWeakLinkage);
    }
    
    // Generate args for call to objc_getAssociatedObject
    llvm::Value *objc_getAssociatedObjectArgs[2];
    objc_getAssociatedObjectArgs[0] = Builder.CreateBitCast(
                                        LoadObjCSelf(), 
                                        Int8PtrTy);
    
    objc_getAssociatedObjectArgs[1] = llvm::ConstantExpr::getBitCast(
                                                          Key, 
                                                          Int8PtrTy);
      
      
    llvm::Value *ret = EmitNounwindRuntimeCall(objc_getAssociatedObjectFn, 
                                               objc_getAssociatedObjectArgs);
    
    if (!PID->getPropertyDecl()->getType()->isObjCRetainableType()) {
      // We have a scalar data type wrapped in an NSValue; unwrap it
      llvm::Value *unwrapped = CreateTempAlloca(getTypes().ConvertType(
        PID->getPropertyDecl()->getType()));
        
      CallArgList args;
      
      args.add(RValue::get(unwrapped),
                           getContext().getPointerType(
                           PID->getPropertyDecl()->getType()
                           ));
      
      // FIXME: The selector could be cached for speed
      llvm::Value* selector = EmitSelRegisterName("getValue:");
      
      CGM.getObjCRuntime().GenerateMessageSend(*this, ReturnValueSlot(),
                                               getContext().VoidTy, selector, 
                                               ret, args);
      
      ret = Builder.CreateLoad(unwrapped);
    }
    
    
    EmitReturnOfRValue(RValue::get(ret), PID->getPropertyDecl()->getType());
    
    FinishFunction();
    
    Hook->RegisterMethodDefinition(OMD, Fn);
}

/// \brief Generates a property setter by using Objective-C associated objects 
void CodeGenFunction::GenerateObjCSetter(ObjCHookDecl *Hook,
                                         const ObjCPropertyImplDecl *PID) {
  ObjCMethodDecl *OMD = PID->getPropertyDecl()->getSetterMethodDecl();
  
  // Get static key for property
  llvm::GlobalVariable* Key = GetPropertyKey(Hook, PID);
  
  // Generate function start
  
  SmallString <256> SymbolName;
  GetMangledNameForLogosMethod("logos_method", OMD, SymbolName);
  
  CodeGenTypes &Types = getTypes();
  
  llvm::FunctionType *MethodTy = Types.GetFunctionType(
                                       Types.arrangeObjCMethodDeclaration(OMD));

  llvm::Function *Fn = llvm::Function::Create(MethodTy, 
                                            llvm::GlobalValue::InternalLinkage, 
                                            SymbolName.str(), &CGM.getModule());
  
  const CGFunctionInfo &FI = Types.arrangeObjCMethodDeclaration(OMD);
  CGM.SetInternalFunctionAttributes(OMD, Fn, FI);
  
  // Create function args (self, _cmd, ...)
  FunctionArgList args;
  args.push_back(OMD->getSelfDecl());
  args.push_back(OMD->getCmdDecl());
  
  for (ObjCMethodDecl::param_const_iterator PI = OMD->param_begin(),
       E = OMD->param_end(); PI != E; ++PI)
  args.push_back(*PI);
  
  CurGD = OMD;
  
  StartFunction(OMD, OMD->getResultType(), Fn, FI, args, PID->getLocStart());
  
  // Generate body
  
  /* void objc_setAssociatedObject(id object, void *key, 
                                 id value, objc_AssociationPolicy policy)*/
  
  // FIXME: objc_AssociationPolicy may not be Int32Ty on all platforms
  llvm::Type *objc_setAssociatedObjectTypes[] = { Int8PtrTy, Int8PtrTy,
                                                  Int8PtrTy, Int32Ty };

  llvm::FunctionType *objc_setAssociatedObjectType = llvm::FunctionType::get(
                                                Builder.getVoidTy(), 
                                                objc_setAssociatedObjectTypes, 
                                                false);
    
  llvm::Constant *objc_setAssociatedObjectFn = CGM.CreateRuntimeFunction(
                                                objc_setAssociatedObjectType, 
                                                "objc_setAssociatedObject");
    
  if (llvm::Function *f = 
                       dyn_cast<llvm::Function>(objc_setAssociatedObjectFn)) {
      f->setLinkage(llvm::Function::ExternalWeakLinkage);
  }
  
  // Create args for call to objc_setAssociatedObject
  llvm::Value *objc_setAssociatedObjectArgs[4];
  
  
  // Load the object being set (the first parameter)
  
  llvm::Value* obj;
  
  if (!PID->getPropertyDecl()->getType()->isObjCRetainableType()) {
    // We have a scalar value; wrap in NSValue
    
    CallArgList args;
    
    args.add(RValue::get(GetAddrOfLocalVar(*(OMD->param_begin()))),
                         getContext().getPointerType(*(OMD->arg_type_begin())));
  
    std::string TypeStr;
    getContext().getObjCEncodingForType(*(OMD->arg_type_begin()), TypeStr);
    
    llvm::Constant *typeEncoding = CGM.GetAddrOfConstantCString(TypeStr);
  
    args.add(RValue::get(typeEncoding), getContext().VoidPtrTy);
    
    // FIXME: The class and selector could be cached for speed
    llvm::Value* selector = EmitSelRegisterName("value:withObjCType:");
    llvm::Value* clazz = EmitGetClassRuntimeCall("NSValue");
    
    obj = CGM.getObjCRuntime().GenerateMessageSend(*this, ReturnValueSlot(),
                                                   getContext().getObjCIdType(),
                                                   selector, clazz, args)
                                                   .getScalarVal();
     
  }else{
    obj = Builder.CreateLoad(GetAddrOfLocalVar(*(OMD->param_begin())));
  }
  
                                      
  llvm::APInt kindInt;
  kindInt = CalculateAssociationPolicy(PID->getPropertyDecl());
  llvm::Constant* assignmentKind = llvm::Constant::getIntegerValue(
                                            Int32Ty,
                                            kindInt);
  
  objc_setAssociatedObjectArgs[0] = Builder.CreateBitCast(
                                        LoadObjCSelf(), 
                                        Int8PtrTy);
  objc_setAssociatedObjectArgs[1] = llvm::ConstantExpr::getBitCast(
                                                        Key, 
                                                        Int8PtrTy);
  objc_setAssociatedObjectArgs[2] = Builder.CreateBitCast(
                                    obj,
                                    Int8PtrTy);
  objc_setAssociatedObjectArgs[3] = assignmentKind;

  EmitNounwindRuntimeCall(objc_setAssociatedObjectFn, 
                                             objc_setAssociatedObjectArgs);
  
  FinishFunction();
  
  Hook->RegisterMethodDefinition(OMD, Fn);
}

// ====== Constructor Generation ====== //


/// Generate the beginning of the constructor

llvm::Function* CodeGenFunction::StartLogosConstructor() {
  FunctionArgList args; // Arguments for the ctor (there are none)
  
  llvm::FunctionType *MethodTy = llvm::FunctionType::get(VoidTy, false);
  llvm::Function *Fn = llvm::Function::Create(MethodTy, llvm::GlobalValue::InternalLinkage, StringRef("logosLocalInit"), &CGM.getModule());
  
  CodeGenTypes &Types = getTypes();
  CurFnInfo = &Types.arrangeNullaryFunction();
    
  // Write ctor prologue
  llvm::BasicBlock *EntryBB = createBasicBlock("entry", Fn);
    
  llvm::Value *Undef = llvm::UndefValue::get(Int32Ty);
  AllocaInsertPt = new llvm::BitCastInst(Undef, Int32Ty, "", EntryBB);
  if (Builder.isNamePreserving())
      AllocaInsertPt->setName("allocapt");
    
  ReturnBlock = getJumpDestInCurrentScope("return");
    
  Builder.SetInsertPoint(EntryBB);
    
  ReturnValue = 0;
    
  EmitStartEHSpec(CurCodeDecl);
    
  PrologueCleanupDepth = EHStack.stable_begin();
  EmitFunctionProlog(*CurFnInfo, Fn, args);
  
  return Fn;
}

llvm::CallInst *CodeGenFunction::EmitSelRegisterName(std::string selector) {
  llvm::Type *sel_registerNameArgTypes[] = { Int8PtrTy };
  llvm::FunctionType *sel_registerNameType = llvm::FunctionType::get(
                                                       Int8PtrTy, 
                                                       sel_registerNameArgTypes, 
                                                       false);
    
  llvm::Constant *sel_registerNameFn = CGM.CreateRuntimeFunction(
                                                          sel_registerNameType, 
                                                          "sel_registerName");
    
  if (llvm::Function *f = dyn_cast<llvm::Function>(sel_registerNameFn)) {
      f->setLinkage(llvm::Function::ExternalWeakLinkage);
  }
    
  llvm::Constant *selectorString = CGM.GetAddrOfConstantCString(selector);
    
  llvm::Value *sel_registerNameArgs[1];
  sel_registerNameArgs[0] = llvm::ConstantExpr::getBitCast(selectorString,
                                                           Int8PtrTy);
    
    
  return EmitNounwindRuntimeCall(sel_registerNameFn, sel_registerNameArgs);
}

/// Generates a call to objc_getClass and returns the result.

llvm::CallInst *CodeGenFunction::EmitGetClassRuntimeCall(std::string ClassName) {
  llvm::Type *objc_getClassArgTypes[] = { Int8PtrTy };
  llvm::FunctionType *objc_getClassType = llvm::FunctionType::get(Int8PtrTy, 
                                                                  objc_getClassArgTypes, 
                                                                  false);
    
  llvm::Constant *objc_getClassFn = CGM.CreateRuntimeFunction(objc_getClassType, 
                                                              "objc_getClass");
    
  if (llvm::Function *f = dyn_cast<llvm::Function>(objc_getClassFn)) {
      f->setLinkage(llvm::Function::ExternalWeakLinkage);
  }
    
  llvm::Constant *classString = CGM.GetAddrOfConstantCString(ClassName);
    
  llvm::Value *objc_getClassArgs[1];
  objc_getClassArgs[0] = llvm::ConstantExpr::getBitCast(classString, Int8PtrTy);
    
    
  return EmitNounwindRuntimeCall(objc_getClassFn, objc_getClassArgs);
}

/// Generates a call to object_getClass and returns the result.
///
/// Class object_getClass(id object)

llvm::CallInst *CodeGenFunction::EmitObjectGetClassRuntimeCall(llvm::Value *O) {
  llvm::Type *argTypes[] = { Int8PtrTy };
  llvm::FunctionType *fnType = llvm::FunctionType::get(Int8PtrTy,
                                                       argTypes,
                                                       false);
    
  llvm::Constant *Fn = CGM.CreateRuntimeFunction(fnType, "object_getClass");
    
  if (llvm::Function *f = dyn_cast<llvm::Function>(Fn)) {
      f->setLinkage(llvm::Function::ExternalWeakLinkage);
  }
  
  llvm::Value *args[1];
  args[0] = Builder.CreateBitCast(O, Int8PtrTy);
    
    
  return EmitNounwindRuntimeCall(Fn, args);
}

/// Generates a call to class_getInstanceVariable and returns the result.

llvm::CallInst *CodeGenFunction::EmitGetIvarRuntimeCall(llvm::Value *clazz,
                                                        std::string ivar) {
  llvm::Type *argTypes[] = { Int8PtrTy, Int8PtrTy };
  llvm::FunctionType *fnType = llvm::FunctionType::get(Int8PtrTy, 
                                                       argTypes, 
                                                       false);
    
  llvm::Constant *Fn = CGM.CreateRuntimeFunction(fnType, 
                                                 "class_getInstanceVariable");
    
  if (llvm::Function *f = dyn_cast<llvm::Function>(Fn)) {
      f->setLinkage(llvm::Function::ExternalWeakLinkage);
  }
    
  llvm::Constant *nameString = CGM.GetAddrOfConstantCString(ivar);
    
  llvm::Value *args[2];
  args[0] = Builder.CreateBitCast(clazz, Int8PtrTy);
  args[1] = Builder.CreateBitCast(nameString, Int8PtrTy);
    
    
  return EmitNounwindRuntimeCall(Fn, args);
}

/// Generates a call to ivar_getOffset and returns the result.

llvm::CallInst *CodeGenFunction::EmitGetIvarOffsetRuntimeCall(
                                                            llvm::Value *ivar) {
  llvm::Type *argTypes[] = { Int8PtrTy };
  llvm::FunctionType *fnType = llvm::FunctionType::get( 
                                          /* FIXME: This probably
                                          isn't the correct return type */
                                                       Int64Ty,
                                                       argTypes, 
                                                       false);
    
  llvm::Constant *Fn = CGM.CreateRuntimeFunction(fnType, 
                                                 "ivar_getOffset");
    
  if (llvm::Function *f = dyn_cast<llvm::Function>(Fn)) {
      f->setLinkage(llvm::Function::ExternalWeakLinkage);
  }
    
  llvm::Value *args[1];
  args[0] = Builder.CreateBitCast(ivar, Int8PtrTy);
  
  return EmitNounwindRuntimeCall(Fn, args);
}


/// Emits a call to MSHookMessageEx with the given class, message, and hook.
/// old should be a pointer to a function pointer that will point to the
/// original method after the hook is complete.

void CodeGenFunction::EmitMessageHook(llvm::CallInst *_class, 
                                      llvm::Value *message, 
                                      llvm::Function* hook, 
                                      llvm::Value *old) {
                                        
  llvm::Type *msgHookExArgTypes[] = { Int8PtrTy, Int8PtrTy, 
                                      Int8PtrTy, Int8PtrTy };
  llvm::FunctionType *msgHookExType = llvm::FunctionType::get(Builder.getVoidTy(), 
                                                              msgHookExArgTypes, 
                                                              false);
  
  llvm::Constant *msHookMsgExFn = CGM.CreateRuntimeFunction(msgHookExType, 
                                                          "MSHookMessageEx");
  
  if (llvm::Function *f = dyn_cast<llvm::Function>(msHookMsgExFn)) {
    f->setLinkage(llvm::Function::ExternalWeakLinkage);
  }
  
  llvm::Value *msHookMsgExArgs[4];
  msHookMsgExArgs[0] = Builder.CreateBitCast(_class, Int8PtrTy);
  msHookMsgExArgs[1] = Builder.CreateBitCast(message, Int8PtrTy);
  msHookMsgExArgs[2] = Builder.CreateBitCast(hook, Int8PtrTy);
  msHookMsgExArgs[3] = Builder.CreateBitCast(old, Int8PtrTy);
  
    
    
  EmitRuntimeCallOrInvoke(msHookMsgExFn, msHookMsgExArgs);
  
}

void CodeGenFunction::EmitNewMethod(llvm::CallInst *_class,
                                    llvm::Value *selector,
                                    llvm::Function *impl,
                                    ObjCMethodDecl *OMD) {

    // Generate string constant for method type encoding
    std::string TypeStr;
    getContext().getObjCEncodingForMethodDecl(OMD, TypeStr);
    
    llvm::Constant *typeEncoding = CGM.GetAddrOfConstantCString(TypeStr);
    
    
    // BOOL class_addMethod(Class cls, SEL name, IMP imp, const char *types)
    llvm::Type *classAddMethodArgTypes[] = { Int8PtrTy, Int8PtrTy, 
                                             Int8PtrTy, Int8PtrTy };
        
    llvm::FunctionType *classAddMethodType = llvm::FunctionType::get(
                                                        Builder.getVoidTy(),
                                                        classAddMethodArgTypes,
                                                        false);
                                                        
    llvm::Constant *classAddMethodFn = CGM.CreateRuntimeFunction(
                                                            classAddMethodType,
                                                            "class_addMethod");
                                                            
    if (llvm::Function *f = dyn_cast<llvm::Function>(classAddMethodFn)) {
      f->setLinkage(llvm::Function::ExternalWeakLinkage);
    }
    
    llvm::Value *classAddMethodArgs[4];
    classAddMethodArgs[0] = Builder.CreateBitCast(_class, Int8PtrTy);
    classAddMethodArgs[1] = Builder.CreateBitCast(selector, Int8PtrTy);
    classAddMethodArgs[2] = Builder.CreateBitCast(impl, Int8PtrTy);
    classAddMethodArgs[3] = Builder.CreateBitCast(typeEncoding, Int8PtrTy);
    
    EmitRuntimeCallOrInvoke(classAddMethodFn, classAddMethodArgs);
}

/// Generates the constructor for an ObjCHookDecl
///
/// This method generates a constructor that calls MSHookMessageEx for each
/// method inside a \@hook container.

void CodeGenFunction::GenerateHookConstructor(ObjCHookDecl *OHD) {
  disableDebugInfo();
  
  llvm::Function *Fn = StartLogosConstructor();
  
  llvm::CallInst *clazz = EmitGetClassRuntimeCall(
                              OHD->getClassInterface()->getNameAsString());
  
  // Get the metaclass, which is used if we're hooking a class method.
  llvm::CallInst *metaclass = EmitObjectGetClassRuntimeCall(clazz);
  
  // Set up hooked and new methods
  for (ObjCContainerDecl::method_iterator M = OHD->meth_begin(),
       MEnd = OHD->meth_end();
       M != MEnd; ++M) {
         
    ObjCMethodDecl *OMD = *M;
    
    
                                
    llvm::Value *selector = CGM.getObjCRuntime().GetSelector(*this, OMD);
    
    // Get the method definition, check for @new
    ObjCMethodDecl *mDecl;
    ObjCInterfaceDecl *CDecl = OHD->getClassInterface();
    
    if (CDecl) {
      if ((mDecl = CDecl->lookupMethod(OMD->getSelector(),
                                       OMD->isInstanceMethod()))) {
        if (mDecl->getImplementationControl() == ObjCMethodDecl::New) {
          EmitNewMethod(clazz, selector, 
                        OHD->GetMethodDefinition(OMD), OMD);
        
          continue;
        }
      }
    }
    
    EmitMessageHook(OMD->isClassMethod() ? metaclass : clazz, selector, 
                    OHD->GetMethodDefinition(OMD),
                    OHD->GetOrigPointer(OMD));
  }
  
  // Add getters/setters to the class
  for (ObjCHookDecl::propimpl_iterator P = OHD->propimpl_begin(),
       PEnd = OHD->propimpl_end();
       P != PEnd; ++P) {
    
    if(ObjCMethodDecl *OMD = (*P)->getPropertyDecl()->getGetterMethodDecl()) {
      llvm::Value *selector = CGM.getObjCRuntime().GetSelector(*this, OMD);

      if (llvm::Function *def = OHD->GetMethodDefinition(OMD))
        EmitNewMethod(clazz, selector, def, OMD);
    }
    
    if(ObjCMethodDecl *OMD = (*P)->getPropertyDecl()->getSetterMethodDecl()) {
      llvm::Value *selector = CGM.getObjCRuntime().GetSelector(*this, OMD);

      if (llvm::Function *def = OHD->GetMethodDefinition(OMD))
        EmitNewMethod(clazz, selector, def, OMD);
    }

  }
  
  FinishFunction(SourceLocation());
  
  CGM.AddGlobalCtor(Fn);
  
  enableDebugInfo();
}

/// Emits an @orig expression
llvm::Value* CodeGenFunction::EmitObjCOrigExpr(const ObjCOrigExpr *E) {
  CGObjCRuntime &Runtime = CGM.getObjCRuntime();
  
  ObjCMethodDecl *OMD = E->getParentMethod();
  
  CallArgList Args;
  
  // Emit self, _cmd
  Args.add(RValue::get(LoadObjCSelf()), getContext().getObjCIdType());
  Args.add(RValue::get(Runtime.GetSelector(*this, OMD->getSelector())), 
                       getContext().getObjCSelType());
  
  // Emit arguments
  for (ObjCOrigExpr::const_arg_iterator I = E->arg_begin(), S = E->arg_end();
       I != S; ++I) {
    
    RValue emittedArg = EmitAnyExpr(*I);
      
    Args.add(emittedArg, I->getType());
  }
  
  // Even though getMessageSendInfo is meant for objc_msgSend, it works
  // just as well for calling the original implementation directly.
  CGObjCRuntime::MessageSendInfo MSI = 
              Runtime.getMessageSendInfo(OMD, 
                                         OMD->getResultType(), 
                                         Args);
  
  assert(isa<ObjCHookDecl>(OMD->getDeclContext()) && "@orig outside of @hook");
  
  // Load and call the original implementation
  ObjCHookDecl *OHD = cast<ObjCHookDecl>(OMD->getDeclContext());
  llvm::Value *Fn = Builder.CreateLoad(OHD->GetOrigPointer(OMD));
  Fn = Builder.CreateBitCast(Fn, MSI.MessengerType);
  
  RValue rvalue = EmitCall(MSI.CallInfo, Fn, ReturnValueSlot(), Args);
  
  return rvalue.getScalarVal();
}

llvm::Value *CodeGenFunction::EmitDynamicIvarOffset(const ObjCIvarDecl *Ivar,
                                           const ObjCInterfaceDecl *Interface) {
  
  llvm::Value *clazz = EmitGetClassRuntimeCall(Interface->getNameAsString());
  llvm::Value *ivar = EmitGetIvarRuntimeCall(clazz, Ivar->getNameAsString());
  llvm::Value *offset = Builder.CreateBitCast(
                                             EmitGetIvarOffsetRuntimeCall(ivar),
                                             Int64Ty);
  
  /*llvm::Value *self = Builder.CreateBitCast(LoadObjCSelf, Int8PtrTy);
  
  llvm::Value *result = Builder.CreateAdd(LoadObjCSelf(), offset);*/
                                             
  return offset;
}

LValue CodeGenFunction::EmitLValueForIvarDynamic(QualType ObjectTy,
                              llvm::Value* Base, const ObjCIvarDecl *Ivar,
                              unsigned CVRQualifiers) {
  const ObjCInterfaceDecl *ID =
    ObjectTy->getAs<ObjCObjectType>()->getInterface();
    
  llvm::Value *Offset = EmitDynamicIvarOffset(Ivar, ID);
  
  return CGM.getObjCRuntime().EmitValueForIvarAtOffset(*this, ID, Base, 
                                                       Ivar, CVRQualifiers,
                                                       Offset);
}
