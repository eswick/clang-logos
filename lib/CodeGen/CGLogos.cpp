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

/// Create the mangled logos name for a hooked method decl.
///
/// logos_method$<class>$<selector>
///
/// Semicolons (:) in selector are replaced with '$'
static void GetMangledNameForLogosMethod(const ObjCMethodDecl *D, SmallVectorImpl<char> &Name) {
    llvm::raw_svector_ostream OS(Name);
    
    std::string sel = D->getSelector().getAsString();
    
    std::replace(sel.begin(), sel.end(), ':', '$');
    
    
    OS << "logos_method$" << D->getClassInterface()->getName() << "$" << sel;
    
}


/// Generate a Logos hook method
///
/// This method takes an ObjCMethodDecl and emits it as
/// a normal, C-like function

void CodeGenFunction::GenerateLogosMethodHook(const ObjCMethodDecl *OMD, ObjCHookDecl *Hook) {
    
    SmallString<256> Name;
    GetMangledNameForLogosMethod(OMD, Name);
    
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

/// Generates the constructor for an ObjCHookDecl
///
/// This method generates a constructor that calls MSHookMessageEx for each
/// method inside a \@hook container.

void CodeGenFunction::GenerateHookConstructor(ObjCHookDecl *OHD) {
  llvm::Function *Fn = StartLogosConstructor();
  
  llvm::CallInst *clazz = EmitGetClassRuntimeCall(
                              OHD->getClassInterface()->getNameAsString());
  
  for (ObjCContainerDecl::method_iterator M = OHD->meth_begin(),
       MEnd = OHD->meth_end();
       M != MEnd; ++M) {
         
    ObjCMethodDecl *OMD = *M;
    
    
                                
    llvm::Value *selector = CGM.getObjCRuntime().GetSelector(*this, OMD);
    
    EmitMessageHook(clazz, selector, 
                    OHD->GetMethodDefinition(OMD), 
                    // TODO: Store old somewhere for use by @orig
                    CGM.EmitNullConstant(getContext().VoidPtrTy));    
  }
  
  FinishFunction(SourceLocation());
  
  CGM.AddGlobalCtor(Fn);
  
}
