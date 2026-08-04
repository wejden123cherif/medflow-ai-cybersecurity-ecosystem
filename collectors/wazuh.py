# collectors/wazuh.py

from __future__ import annotations

import os
import requests
import urllib3

from collectors.base import BaseCollector

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)


DEFAULT_WAZUH_LIMIT = 20
DEFAULT_WAZUH_MIN_RULE_LEVEL = 4
DEFAULT_WAZUH_RECENT_HOURS = 24
DEFAULT_WAZUH_LOOKBACK_DAYS = 30

DEFAULT_WAZUH_EXCLUDED_RULE_IDS = {
    "19005",
    "19007",
    "61109"
}

DEFAULT_WAZUH_EXCLUDED_GROUPS = {
    "sca"
}


class WazuhCollector(BaseCollector):

    name = "wazuh"


    def __init__(self):

        self.url = os.getenv(
            "WAZUH_URL"
        )

        self.indexer_url = os.getenv(
            "WAZUH_INDEXER_URL",
            "https://localhost:9200"
        )

        self.user = os.getenv(
            "WAZUH_USER",
            "wazuh-wui"
        )

        self.password = os.getenv(
            "WAZUH_PASSWORD",
            "MyS3cr37P450r.*-"
        )

        self.indexer_user = os.getenv(
            "WAZUH_INDEXER_USER",
            "admin"
        )

        self.indexer_password = os.getenv(
            "WAZUH_INDEXER_PASSWORD",
            "SecretPassword"
        )



    # ==========================================================
    # PUBLIC ENTRYPOINT
    # ==========================================================

    def collect(self):

        alerts, metadata = self.collect_manager()


        if alerts:
            return alerts, metadata


        # fallback to indexer
        alerts, metadata = self.collect_indexer()


        return alerts, metadata



    # ==========================================================
    # WAZUH MANAGER API
    # ==========================================================

    def collect_manager(self):

        metadata = {
            "source_system": "wazuh_manager",
            "data_source": "wazuh_live"
        }


        if not self.url:

            metadata["failure_reason"] = (
                "WAZUH_URL not configured"
            )

            return None, metadata


        try:

            token = self.authenticate()


            response = requests.get(
                f"{self.url}/alerts",
                headers={
                    "Authorization":
                    f"Bearer {token}"
                },
                params={
                    "limit": DEFAULT_WAZUH_LIMIT,
                    "sort": "-timestamp"
                },
                verify=False,
                timeout=10
            )


            if response.status_code != 200:

                metadata["failure_reason"] = (
                    f"Wazuh API HTTP {response.status_code}"
                )

                return None, metadata



            raw_alerts = (
                response
                .json()
                .get("data", {})
                .get("affected_items", [])
            )


            if not raw_alerts:

                metadata["failure_reason"] = (
                    "Wazuh returned zero alerts"
                )

                return None, metadata



            return (
                self.normalize_alerts(raw_alerts),
                metadata
            )


        except Exception as e:

            metadata["failure_reason"] = (
                f"Wazuh manager error: {e}"
            )

            return None, metadata




    def authenticate(self):

        response = requests.post(

            f"{self.url}/security/user/authenticate",

            auth=(
                self.user,
                self.password
            ),

            verify=False,

            timeout=5
        )


        if response.status_code != 200:

            raise Exception(
                f"Authentication failed {response.status_code}"
            )


        return (
            response
            .json()
            ["data"]
            ["token"]
        )



    # ==========================================================
    # WAZUH INDEXER
    # ==========================================================

    def collect_indexer(self):

        metadata = {

            "source_system":
                "wazuh_indexer",

            "data_source":
                "wazuh_live"

        }


        try:

            query = {

                "size":
                    DEFAULT_WAZUH_LIMIT,

                "sort":[

                    {
                        "@timestamp":
                        {
                            "order":"desc"
                        }
                    }

                ],

                "query":{

                    "range":{

                        "@timestamp":{

                            "gte":
                            f"now-{DEFAULT_WAZUH_RECENT_HOURS}h"

                        }

                    }

                }

            }



            response = requests.get(

                f"{self.indexer_url}/wazuh-alerts-*/_search",

                auth=(

                    self.indexer_user,

                    self.indexer_password

                ),

                json=query,

                verify=False,

                timeout=10

            )



            if response.status_code != 200:

                metadata["failure_reason"] = (
                    f"Indexer HTTP {response.status_code}"
                )

                return None, metadata



            hits = (

                response
                .json()
                .get("hits", {})
                .get("hits", [])
            )


            alerts = [

                hit.get(
                    "_source",
                    {}
                )

                for hit in hits

            ]


            if not alerts:

                metadata["failure_reason"] = (
                    "Indexer returned no alerts"
                )

                return None, metadata



            return (

                self.normalize_alerts(
                    alerts
                ),

                metadata

            )



        except Exception as e:

            metadata["failure_reason"] = (
                f"Wazuh indexer error: {e}"
            )

            return None, metadata




    # ==========================================================
    # NORMALIZATION
    # ==========================================================


    def normalize_alerts(
            self,
            alerts:list
    ):


        normalized=[]



        for index, alert in enumerate(alerts):


            rule = alert.get(
                "rule",
                {}
            )


            agent = alert.get(
                "agent",
                {}
            )


            data = alert.get(
                "data",
                {}
            )



            mitre_id="unknown"


            mitre = rule.get(
                "mitre",
                {}
            )


            if mitre:

                ids = mitre.get(
                    "id",
                    []
                )

                if ids:

                    mitre_id = ids[0]



            level = int(
                rule.get(
                    "level",
                    0
                )
                or 0
            )



            normalized.append({

                "id":
                    f"WZ-{index+1:03d}",


                "timestamp":
                    alert.get(
                        "timestamp",
                        alert.get(
                            "@timestamp",
                            ""
                        )
                    ),


                "source_ip":
                    (
                        data.get("srcip")
                        or
                        data.get("src_ip")
                        or
                        agent.get(
                            "ip",
                            "unknown"
                        )
                    ),


                "destination":
                    agent.get(
                        "name",
                        "unknown"
                    ),



                "event_type":

                    rule.get(
                        "description",
                        "unknown"
                    ),



                "technique_hint":
                    mitre_id,



                "severity":
                    self.map_severity(
                        level
                    ),



                "raw_log":
                    str(
                        alert.get(
                            "full_log",
                            ""
                        )
                    )[:500],



                "wazuh_rule_id":
                    rule.get(
                        "id",
                        ""
                    ),



                "wazuh_rule_level":
                    level,



                "wazuh_rule_groups":
                    rule.get(
                        "groups",
                        []
                    ),



                "agent_name":
                    agent.get(
                        "name",
                        "unknown"
                    ),



                "agent_id":
                    agent.get(
                        "id",
                        "000"
                    ),



                "source_system":
                    "wazuh",



                "data_source":
                    "wazuh_live",



                "risk_score":
                    self.calculate_risk(
                        level
                    ),



                "risk_priority":
                    self.risk_priority(
                        level
                    )

            })


        return normalized




    # ==========================================================
    # HELPERS
    # ==========================================================


    def map_severity(
        self,
        level:int
    ):

        if level >= 12:
            return "critical"

        if level >=8:
            return "high"

        if level>=4:
            return "medium"

        return "low"



    def calculate_risk(
        self,
        level:int
    ):

        return min(
            100,
            level*6
        )



    def risk_priority(
        self,
        level:int
    ):


        if level>=12:
            return "high"

        if level>=8:
            return "medium"

        return "low"