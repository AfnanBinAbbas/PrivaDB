class PolicyFetchError(Exception):
    """Raised when the policy URL cannot be fetched."""
    pass

class PolicyParseError(Exception):
    """Raised when the policy HTML cannot be parsed."""
    pass

class AnalysisError(Exception):
    """Raised when an error occurs during policy analysis."""
    pass
