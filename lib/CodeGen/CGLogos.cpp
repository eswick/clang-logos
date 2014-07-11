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

void CodeGenFunction::GenerateLogosMethodHook(const ObjCMethodDecl *OMD, const ObjCHookDecl *Hook) {
    
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
    
}
