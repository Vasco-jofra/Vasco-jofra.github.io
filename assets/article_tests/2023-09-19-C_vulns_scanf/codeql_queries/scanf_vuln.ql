import cpp

// ====================
// Format functions
abstract class FormatFunction extends Function {
  abstract int getFormatArgumentPosition();
}

class ScanfFunction extends FormatFunction {
  ScanfFunction() { this.getName() = "scanf" }

  override int getFormatArgumentPosition() { result = 0 }
}

class FscanfFunction extends FormatFunction {
  FscanfFunction() { this.getName() = "fscanf" }

  override int getFormatArgumentPosition() { result = 1 }
}

class SscanfFunction extends FormatFunction {
  SscanfFunction() { this.getName() = "sscanf" }

  override int getFormatArgumentPosition() { result = 1 }
}

// ====================
// Helper functions
// Returns the number of format arguments that a given format consumes
bindingset[format]
int nrOfFormatArgsConsumedBy(string format) { result = count(format.regexpFind("%[^*%]", _, _)) }

// Returns argument number of the format argument after the format we receive
bindingset[format]
int nextFormatArgNr(string format, FormatFunction scanfLikeFunction) {
  result = scanfLikeFunction.getFormatArgumentPosition() + nrOfFormatArgsConsumedBy(format) + 1
}

// ====================
// Base classes
class ScanfLikeFunctionCall extends FunctionCall {
  FormatFunction scanfLikeFunction;
  string formatArgument;

  ScanfLikeFunctionCall() {
    (
      scanfLikeFunction instanceof ScanfFunction or
      scanfLikeFunction instanceof FscanfFunction or
      scanfLikeFunction instanceof SscanfFunction
    ) and
    this.getTarget() = scanfLikeFunction and
    formatArgument = this.getArgument(scanfLikeFunction.getFormatArgumentPosition()).getValue()
  }

  string getFormatArgument() { result = formatArgument }
}

abstract class VulnerableScanfLikeFunctionCall extends ScanfLikeFunctionCall {
  abstract string getBadFormat();

  abstract int getBadFormatOffset();

  abstract Expr getBadFormatArgExpr();

  abstract int getBufSize();
}

// Vulnerable scanf-like calls with %s or %[AAA] or %[^AAA]
class VulnerableScanfPercentageSFunctionCall extends VulnerableScanfLikeFunctionCall {
  string badFormat;
  int badFormatOffset;
  Expr badFormatExpr;

  VulnerableScanfPercentageSFunctionCall() {
    (
      scanfLikeFunction instanceof ScanfFunction or
      scanfLikeFunction instanceof FscanfFunction or
      // TODO: needs more strict checking to remove FPs. Sometimes this is ok.
      scanfLikeFunction instanceof SscanfFunction
    ) and
    badFormat = this.getFormatArgument().regexpFind("%(s|\\[[^%]*\\])", _, badFormatOffset) and
    badFormatExpr =
      this.getArgument(nextFormatArgNr(this.getFormatArgument().substring(0, badFormatOffset),
          scanfLikeFunction))
  }

  override string getBadFormat() { result = badFormat }

  override int getBadFormatOffset() { result = badFormatOffset }

  override Expr getBadFormatArgExpr() { result = badFormatExpr }

  override int getBufSize() { result = -1 }
}

// ====================
// Vulnerable scanf-like calls with %XXs
class VulnerableScanfPercentageXXSFunctionCall extends VulnerableScanfLikeFunctionCall {
  string badFormat;
  int badFormatOffset;
  Expr badFormatExpr;
  int widthModifier;
  int bufSize;

  // TODO: Since there are multiple potential bad formats for a given format, this query will return all combinations. Think about how to fix this.
  VulnerableScanfPercentageXXSFunctionCall() {
    badFormat = this.getFormatArgument().regexpFind("%([0-9]+)l?s", _, badFormatOffset) and
    badFormatExpr =
      this.getArgument(nextFormatArgNr(this.getFormatArgument().substring(0, badFormatOffset),
          scanfLikeFunction)) and
    widthModifier = badFormat.substring(1, badFormat.length() - 1).toInt() and
    (
      badFormatExpr instanceof VariableAccess and
      (
        // char[SZ] style arguments
        badFormatExpr.getUnderlyingType().(ArrayType).hasArraySize() and
        bufSize = badFormatExpr.getUnderlyingType().getSize() //   and widthModifier >= bufSize
        or
        not badFormatExpr.getUnderlyingType().(ArrayType).hasArraySize() and
        // char* style arguments
        // exists(AllocationExpr ae | targetVariableAccess.getEnclosingVariable() = ae.getEnclosingVariable() and
        bufSize = -1
      )
      or
      not badFormatExpr instanceof VariableAccess and bufSize = -2
    )
  }

  override string getBadFormat() { result = badFormat }

  override int getBadFormatOffset() { result = badFormatOffset }

  override Expr getBadFormatArgExpr() { result = badFormatExpr }

  override int getBufSize() { result = bufSize }
}

// ====================
// Queries
// ====================
// from AllocationExpr ae, int size
// where
//   exists(ae.getSizeBytes()) and size = ae.getSizeBytes()
//   or
//   not exists(ae.getSizeBytes()) and size = 0
// select ae, ae.getParent(), ae.getParent(), ae.getSizeExpr(), size
// from Stmt stmt
// where stmt.getAChild() instanceof AllocationExpr
// select stmt
// ====================
// from AllocationExpr ae, int size
// where
//   exists(ae.getSizeBytes()) and size = ae.getSizeBytes()
//   or
//   not exists(ae.getSizeBytes()) and size = 0
// select ae, ae.getParent(), ae.getParent(), ae.getSizeExpr(), size
// ====================
// from VulnerableScanfLikeFunctionCall f, Expr e
from VulnerableScanfPercentageXXSFunctionCall f
select f, f.getFormatArgument(), f.getBadFormat(), f.getBadFormatOffset()
