"""Web Workbench traffic importers (WB-P10a).

Convert external traffic captures into the workbench's own normalized transport
types so imported requests behave exactly like live-captured ones. The HAR
importer is pure, offline, fail-closed, and bounded.
"""

from src.web_workbench.imports.har import (
    HarImportError,
    ImportedExchange,
    import_har,
)
from src.web_workbench.imports.graphql import (
    GraphQLImportError,
    import_graphql_introspection,
)
from src.web_workbench.imports.openapi import (
    OpenApiImportError,
    import_openapi,
)
from src.web_workbench.imports.postman import (
    PostmanImportError,
    import_postman,
)
from src.web_workbench.imports.wsdl import (
    WsdlImportError,
    import_wsdl,
)

__all__ = [
    "GraphQLImportError",
    "HarImportError",
    "ImportedExchange",
    "OpenApiImportError",
    "PostmanImportError",
    "WsdlImportError",
    "import_graphql_introspection",
    "import_har",
    "import_openapi",
    "import_postman",
    "import_wsdl",
]
