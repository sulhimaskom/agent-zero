from duckduckgo_search import DDGS
from python.helpers.constants import Search


def search(
    query: str,
    results: int = Search.DDG_DEFAULT_RESULTS,
    region: str = Search.DDG_DEFAULT_REGION,
    time: str = Search.DDG_DEFAULT_TIME_LIMIT,
) -> list[str]:

    ddgs = DDGS()
    src = ddgs.text(
        query,
        region=region,
        safesearch=Search.DDG_DEFAULT_SAFESEARCH,
        timelimit=time,
        max_results=results,
    )
    result_list = []
    for s in src:
        result_list.append(str(s))
    return result_list
