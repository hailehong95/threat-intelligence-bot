import requests
from shodan import Shodan
from tlglogging.config import logger


def shodan_search_ip(key, ip):
    """
    Returns all services that have been found on the given host IP.
    """
    try:
        sd = Shodan(key)
        resp = sd.host(ip)
    except Exception as ex:
        logger.warning(str(ex))
    else:
        return resp
    return None


def shodan_count_result(key, query, facets=""):
    """
    returns the total number of results that matched the query and any facet information that was requested.
    """
    try:
        sd = Shodan(key)
        resp = sd.count(query=query, facets=facets)
    except Exception as ex:
        logger.warning(str(ex))
    else:
        return resp
    return None


def shodan_search_query(key, query, facets="", limit=20):
    """
    Search Shodan using the same query syntax as the website
    and use facets to get summary information for different properties.
    - query: https://beta.shodan.io/search/filters
    - facets: https://beta.shodan.io/search/facet
    """
    try:
        sd = Shodan(key)
        resp = sd.search(query=query, facets=facets, limit=limit)
    except Exception as ex:
        logger.warning(str(ex))
    else:
        return resp
    return None


def shodan_list_facets(key):
    """
    List all search facets
    This method returns a list of facets that can be used to get a breakdown of the top values for a property. 
    """
    try:
        sd = Shodan(key)
        resp = sd.search_facets()
    except Exception as ex:
        logger.warning(str(ex))
    else:
        return resp
    return None


def shodan_list_filters(key):
    """
    List all filters that can be used when searching
    This method returns a list of search filters that can be used in the search query.
    """
    try:
        sd = Shodan(key)
        resp = sd.search_filters()
    except Exception as ex:
        logger.warning(str(ex))
    else:
        return resp
    return None


def shodan_search_token(key, query):
    """
    Break the search query into tokens
    This method lets you determine which filters are being used by the query string and what
    parameters were provided to the filters.
    """
    try:
        sd = Shodan(key)
        resp = sd.search_tokens(query=query)
    except Exception as ex:
        logger.warning(str(ex))
    else:
        return resp
    return None
