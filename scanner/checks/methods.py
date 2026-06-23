import aiohttp
from typing import List
from urllib.parse import urlparse
from models.vulnerability import Vulnerability

async def method_check(url: str) -> List[Vulnerability]:
    parsed = urlparse(url)
    root_url = f"{parsed.scheme}://{parsed.netloc}/"
    
    try:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.request("OPTIONS", root_url, timeout=5) as response:
                allow_header = response.headers.get("Allow") or response.headers.get("allow")
                
                if allow_header:
                    # Parse allowable methods (comma or space separated)
                    methods = [
                        m.strip().upper() 
                        for m in allow_header.replace(",", " ").split() 
                        if m.strip()
                    ]
                    
                    dangerous_methods = {"PUT", "DELETE", "PATCH", "TRACE", "CONNECT"}
                    exposed_dangerous = [m for m in methods if m in dangerous_methods]
                    
                    if exposed_dangerous:
                        return [
                            Vulnerability(
                                endpoint="/",
                                method="OPTIONS",
                                issue="Exposed HTTP Methods",
                                severity="LOW",
                                confidence="HIGH",
                                description=(
                                    f"The server exposes potentially dangerous or unnecessary HTTP methods: "
                                    f"{', '.join(exposed_dangerous)}. Full allowed list: {allow_header}."
                                ),
                                recommendation=(
                                    "Disable unused or dangerous HTTP methods (such as PUT, DELETE, PATCH, "
                                    "TRACE, CONNECT) on the server if they are not explicitly required."
                                )
                            )
                        ]
    except Exception as e:
        print(f"Method check error scanning {root_url}: {e}")
        
    return []
