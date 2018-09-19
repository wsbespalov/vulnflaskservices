SETTINGS = {
    "postgres": {
        "user": 'admin',
        "password": '123',
        "database": "updater_db",
        "host": "localhost",
        "port": "5432",
        "reconnect_count": 1000,
        "updater_offset": 1000
    },
    "queue": {
        "host": 'localhost',
        "port": 6379,
        "db": 0,
        "charset": "utf-8",
        "decode_responses": True,
        # Channels
        "channel": "start_processing",
        "channel_complete": "search_complete",
        "vulnerability_channel": "vulnerabilityServiceChannel",
        # Prefixes
        "prefix_cv_search_start": "search::",
        "prefix_cv_search_complete": "create::",
        "prefix_text_search_cv_start": "elasticsearch-cv::",
        "prefix_text_search_descr_start": "elasticsearch-descr::",
        "prefix_text_search_cv_descr_start": "elasticsearch-cv-descr::",
        "prefix_text_search_complete": "elasticsearch-result::",
        "prefix_complete_get_vulnerability": "result::",
        # Messages
        "message_cv_search_start": "start_search",
        "message_text_search_cv_start": "elasticsearch-cv",
        "message_text_search_descr_start": "elasticsearch-descr",
        "message_text_search_cv_descr_start": "elasticsearch-cv-descr",
        "message_to_get_vulnerability": "getVulnerability",
        "message_to_kill_search": "message_to_kill_search",
        # Queues
        "modified_queue": "vulnerabilities:modified",
        "new_queue": "vulnerabilities:new",
        "stats_channel": "stats_channel",
        "stats_collection": "stats_collection",
        "stats_message": "stats_message",
        "database_stats_collection": "database_stats_collection",
        "database_stats_message": "database_stats_message",
        "notify_new_elements_channel": "new_elements_channel",
        "notify_new_elements_message": "vulnerability_new_elements",
        "notify_modified_elements_message": "vulnerability_modified_elements",
    },
    "cache": {
        "host": 'localhost',
        "port": 6379,
        "db": 3,
        "separator": "::",
        "index": "index",
        "key_expire_time_in_sec": 60*60*48,
        "charset": "utf-8",
        "decode_responses": True,
    },
    "stats": {
        "host": 'localhost',
        "port": 6379,
        "db": 1,
        "charset": "utf-8",
        "decode_responses": True,
    },
    "mongo": {
        "host": "localhost",
        "port": 27017,
        "db": "surepatch",
        "user": "",
        "password": "",
        "collection_updater": "updater_stats",
        "collection_stats": "stats_flags",
        "collection_database": "database_stats",
        "collection_vulnerability_new": "vulnerability_new_elements",
        "collection_vulnerability_modified": "vulnerability_modified_elements",
    },
    "vulnerabilities": {
        "drop_vulnerabilities_table": False
    },
    "cv": {
        "drop_cv_table": False
    },
    "cve": {
        "drop_cve_table": False,
        "start_year": 2002,
        "download_retry_count": 5,
        "download_retry_timeout_in_sec": 60
    },
    "cwe": {
        "drop_cwe_table": False,
        "source": "http://cwe.mitre.org/data/xml/cwec_v2.8.xml.zip"
    },
    "capec": {
        "drop_capec_table": False,
        "source": "http://capec.mitre.org/data/xml/capec_v2.6.xml"
    },
    "npm": {
        "drop_npm_table": False,
        "source": "https://api.nodesecurity.io/advisories"
    },
    "snyk": {
        "drop_snyk_table": False
    },
    "d2sec": {
        "drop_d2sec_table": False
    },
    "ms": {
        "drop_ms_table": False
    },
    "hacker_news": {
        "drop_hacker_news_table": False
    },
    "enable_extra_logging": True,
    "enable_results_logging": False,
    "enable_exception_logging": True,
    "enable_system_logging": True,
    "start_delay": 5,
    "updater_delay": 1200,
    "updater_runtime": "1:00",
    "undefined": "undefined",
    "helpers_collection": "helpers_collection",
    "snyk_fixture_filename": "snyk.fixture.json",
    "monitor_runtime": 1,  # minute
    "monitor_timeout": 20,  # sec
    "show_monitor_ping": 'no'
}
