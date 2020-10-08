/*
 * Copyright 2002-2020 Intel Corporation.
 *
 * This software is provided to you as Sample Source Code as defined in the accompanying
 * End User License Agreement for the Intel(R) Software Development Products ("Agreement")
 * section 1.L.
 *
 * This software and the related documents are provided as is, with no express or implied
 * warranties, other than those that are expressly stated in the License.
 */

/*
 * adapted from the itrace.ccp example
 *   --jofra
 */

#include <stdio.h>
#include "pin.H"

FILE* trace;
bool should_print = false;

// prints the intruction pointer
VOID printip(VOID* ip) {
  if (should_print) {
    fprintf(trace, "%p\n", ip);
  } else if (ip == (VOID*)(0x555555554000 + 0x5ac)) { // plt['system']
    // when we reach the end of 'main' start tracing
    should_print = true;
  }
}

// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID* v) {
  // Insert a call to printip before every instruction, and pass it the IP
  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)printip, IARG_INST_PTR, IARG_END);
}

// This function is called when the application exits
VOID Fini(INT32 code, VOID* v) {
  fprintf(trace, "#eof\n");
  fclose(trace);
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage() {
  PIN_ERROR("This Pintool prints the IPs of every instruction executed\n" + KNOB_BASE::StringKnobSummary() + "\n");
  return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char* argv[]) {
  trace = fopen("trace.out", "w");

  // Initialize pin
  if (PIN_Init(argc, argv))
    return Usage();

  // Register Instruction to be called to instrument instructions
  INS_AddInstrumentFunction(Instruction, 0);

  // Register Fini to be called when the application exits
  PIN_AddFiniFunction(Fini, 0);

  // Start the program, never returns
  PIN_StartProgram();

  return 0;
}
