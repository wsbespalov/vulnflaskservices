import os
import re
import json
import ast
import bz2
import gzip
import enum
import requests
import platform
import urllib.request as req
import zipfile
from dateutil.parser import parse as parse_datetime
from datetime import datetime
from math import floor
from io import BytesIO

from logger import LOGERR_IF_ENABLED


class CVEItemIndexes(enum.Enum):
    cve_id = 0
    cwe = 1
    references = 2
    vulnerable_configuration = 3
    data_type = 4
    data_version = 5
    data_format = 6
    description = 7
    published = 8
    modified = 9
    access = 10
    impact = 11
    cvss_vector = 12
    cvss_time = 13
    cvss = 14


class ExtendedCVEItemIndexes(enum.Enum):
    length = 28
    cve_id = 0
    cwe = 1
    references = 2
    vulnerable_configuration = 3
    data_type = 4
    data_version = 5
    data_format = 6
    description = 7
    published = 8
    modified = 9
    access = 10
    impact = 11
    cvss_vector = 12
    cvss_time = 13
    cvss = 14
    component = 15
    component_version_list = 16
    component_version_string = 17
    source = 18
    cve_list = 19
    cpe_list = 20
    cwe_id_list = 21
    generated_vulnerability_id = 22
    vulnerable_versions = 23
    patched_versions = 24
    npm_list = 25
    author = 26
    recommendations = 27
    ms_list = 28


def get_module_name(__file__):
    full_path = os.path.abspath(__file__)
    return full_path.split('/')[-1][:-3]


SOURCE_MODULE = '[{0}] :: '.format(get_module_name(__file__))


def now():
    """
    Get current time in string format.
    """
    return datetime.now().strftime("%H:%M:%S")


def make_access(access_in_item):
    if isinstance(access_in_item, str):
        return deserialize_json_for_postgres(access_in_item)
    if isinstance(access_in_item, dict):
        return access_in_item
    if access_in_item is None or access_in_item == "":
        return dict(vector="", complexity="", authentication="")


def make_impact(impact_in_item):
    if isinstance(impact_in_item, str):
        return deserialize_json_for_postgres(impact_in_item)
    if isinstance(impact_in_item, dict):
        return impact_in_item
    if impact_in_item is None or impact_in_item == "":
        return dict(confidentiality="", integrity="", availability="")


def make_digits(s):
    return re.sub(r"\D", "", s)


def make_cwe_list(cwe_in_item):
    return deserialize_json_for_postgres(cwe_in_item)


def make_cwe_id_list(cwe_in_item):
    cwe_list = make_cwe_list(cwe_in_item)
    return [make_digits(cwe) for cwe in cwe_list]


def convert_capec(capec_in_list):
    if isinstance(capec_in_list, str):
        return json.loads(capec_in_list)
    elif isinstance(capec_in_list, list):
        return capec_in_list
    elif isinstance(capec_in_list, dict):
        return capec_in_list
    return []


def make_capec(capec_list):
    return [convert_capec(capec_in_list) for capec_in_list in capec_list]


def make_metadata(metadata):
    if isinstance(metadata, str):
        try:
            return json.loads(metadata)
        except Exception as ex:
            return dict(npm=[])
    if isinstance(metadata, dict):
        return metadata
    if metadata is None or metadata == "":
        return dict(npm=[])


def reformat_vulnerability_for_output(item):
    id_ = item.get("id", None)

    if id_ is not None:
        return dict(
            _id=id_,
            Published=unify_time(item.get("publushed", datetime.utcnow())),
            Modified=unify_time(item.get("modified", datetime.utcnow())),
            access=make_access(item.get("access", None)),
            impact=make_impact(item.get("impact", None)),
            cvss_time=unify_time(item.get("cvss_time", datetime.utcnow())),
            cvss=item.get("cvss", 0.0),
            cwe=make_cwe_list(item.get("cwe_elements", [])),
            cwe_id=make_cwe_id_list(item.get("cwe", [])),
            title=item.get("vulnerability_id", ""),
            description=item.get("description", ""),
            rank=floor(float(item.get("cvss", 0.0))),
            __v=0,
            capec=make_capec(item.get("capec_elements", [])),
            vulnerable_configurations=[],
            vulnerable_configuration=item.get("vulnerable_configuration", []),
            cve_references=item.get("references", []),
            vector_string=item.get("vector_string", ""),
            metadata=make_metadata(item.get("metadata", {
                "npm": [],
                "snyk": [],
                "ms": [],
                "hacker_news": []
            }))
        )

    return None


def fill_json_structure_for_api_ui(content_for_search, one_search_result):
    return dict(
        project_id=content_for_search["project_id"],
        organization_id=content_for_search["organization_id"],
        set_id=content_for_search["set_id"],
        component=dict(
            name=content_for_search["component"]["name"],
            version=content_for_search["component"]["version"]
        ),
        vulnerability=one_search_result
    )


def unify_time(dt):
    if isinstance(dt, str):
        if 'Z' in dt:
            dt = dt.replace('Z', '')
        return parse_datetime(dt).strftime("%Y-%m-%d %H:%M:%S")

    if isinstance(dt, datetime):
        return parse_datetime(str(dt)).strftime("%Y-%m-%d %H:%M:%S")


def serialize_as_json_for_cache(element):
    def dt_converter(o):
        if isinstance(o, datetime):
            return o.__str__()
    try:
        return json.dumps(element, default=dt_converter)
    except Exception as ex:
        LOGERR_IF_ENABLED(SOURCE_MODULE, "[-] Got exception during serializing: {0}".format(ex))
        return None


def deserialize_as_json_for_cache(element):
    if element is None:
        LOGERR_IF_ENABLED(SOURCE_MODULE, "[-] Element for deserialize is None!")
    try:
        return json.loads(element)
    except Exception as ex:
        LOGERR_IF_ENABLED(SOURCE_MODULE, "[-] Got exception during deserializing: {0}".format(ex))
        return None


def deserialize_json_for_postgres(source):
    if isinstance(source, list):
        return source
    else:
        try:
            a = ast.literal_eval(source)
        except Exception:
            LOGERR_IF_ENABLED(SOURCE_MODULE, '[-] Got invalid format for deserialize: {0}'.format(source))
            return {}
    if isinstance(a, dict):
        return a
    return json.loads(a)


def get_file(getfile, unpack=True, raw=False, HTTP_PROXY=None):
    if platform.system().lower() == "linux":
        try:
            if HTTP_PROXY:
                proxy = req.ProxyHandler({'http': HTTP_PROXY, 'https': HTTP_PROXY})
                auth = req.HTTPBasicAuthHandler()
                opener = req.build_opener(proxy, auth, req.HTTPHandler)
                req.install_opener(opener)

            data = response = req.urlopen(getfile)

            if raw:
                return data

            if unpack:
                if 'gzip' in response.info().get('Content-Type'):
                    current_directory = os.path.dirname(os.path.abspath(__file__))
                    tmp_file = "data.json"
                    full_path = "".join([
                        current_directory, "/", tmp_file
                    ])
                    with open(full_path, "wb") as outfile:
                        outfile.write(gzip.decompress(response.read()))
                    out = open(full_path, 'r').read()
                    return out, response
                elif 'bzip2' in response.info().get('Content-Type'):
                    data = BytesIO(bz2.decompress(response.read()))
                elif 'zip' in response.info().get('Content-Type'):
                    fzip = zipfile.ZipFile(BytesIO(response.read()), 'r')
                    length_of_namelist = len(fzip.namelist())
                    if length_of_namelist > 0:
                        data = BytesIO(fzip.read(fzip.namelist()[0]))
            return data, response
        except Exception as ex:
            return None, str(ex)

    elif platform.system().lower() == "darwin":
        try:
            if HTTP_PROXY:
                proxy = req.ProxyHandler({'http': HTTP_PROXY, 'https': HTTP_PROXY})
                auth = req.HTTPBasicAuthHandler()
                opener = req.build_opener(proxy, auth, req.HTTPHandler)
                req.install_opener(opener)

            data = response = req.urlopen(getfile)

            if raw:
                return data

            if unpack:
                if 'gzip' in response.info().get('Content-Type'):
                    buf = BytesIO(response.read())
                    data = gzip.GzipFile(fileobj=buf)
                elif 'bzip2' in response.info().get('Content-Type'):
                    data = BytesIO(bz2.decompress(response.read()))
                elif 'zip' in response.info().get('Content-Type'):
                    fzip = zipfile.ZipFile(BytesIO(response.read()), 'r')
                    length_of_namelist = len(fzip.namelist())
                    if length_of_namelist > 0:
                        data = BytesIO(fzip.read(fzip.namelist()[0]))
            return data, response
        except Exception as ex:
            return None, str(ex)


def tuple_to_json(src):
    item = list(src)
    return dict(
        id=item[0],
        vulnerability_id=item[CVEItemIndexes.cve_id.value + 1],
        componentversion=item[CVEItemIndexes.componentversion.value + 1],
        cwe=item[CVEItemIndexes.cwe.value + 1],
        capec=item[CVEItemIndexes.capec.value + 1],
        references=item[CVEItemIndexes.references.value + 1],
        vulnerable_configuration=item[CVEItemIndexes.vulnerable_configuration.value + 1],
        data_type=item[CVEItemIndexes.data_type.value + 1],
        data_version=item[CVEItemIndexes.data_version.value + 1],
        data_format=item[CVEItemIndexes.data_format.value + 1],
        description=item[CVEItemIndexes.description.value + 1],
        published=item[CVEItemIndexes.published.value + 1],
        modified=item[CVEItemIndexes.modified.value + 1],
        access=item[CVEItemIndexes.access.value + 1],
        impact=item[CVEItemIndexes.impact.value + 1],
        vector_string=item[CVEItemIndexes.cvss_vector.value + 1],
        cvss_time=item[CVEItemIndexes.cvss_time.value + 1],
        cvss=item[CVEItemIndexes.cvss.value + 1],
    )


def convert_search_result_from_tuple_to_json(elements: list):
    found_items = []

    if isinstance(elements, tuple):
        found_items.append(
            tuple_to_json(elements)
        )
    elif isinstance(elements, list):
        for element in elements:
            found_items.append(
                tuple_to_json(
                    element
                )
            )
    return found_items


def append_element_if_not_in_target_list(element, target_list: list):
    if isinstance(target_list, list):
        if element not in target_list:
            target_list.append(element)
    return target_list


def append_list_if_not_in_target_list(src_list: list, target_list: list):
    if isinstance(src_list, list) and isinstance(target_list, list):
        for element in src_list:
            if element not in target_list:
                target_list.append(element)
    return target_list


def check_internet_connection():
    url = 'http://www.google.com/'
    timeout = 5
    try:
        _ = requests.get(url, timeout=timeout)
        return True
    except requests.ConnectionError:
        LOGERR_IF_ENABLED(SOURCE_MODULE, "[I] Internet connection is lost")
    return False
