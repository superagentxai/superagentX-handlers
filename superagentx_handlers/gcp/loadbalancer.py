import asyncio
import json
import logging
import os
import pathlib

from typing import Dict, List, Any
from google.cloud import compute_v1
from google.api_core import exceptions
from google.oauth2 import service_account
from superagentx.handler.base import BaseHandler
from superagentx.handler.decorators import tool
from superagentx.utils.helper import sync_to_async, iter_to_aiter

logger = logging.getLogger(__name__)


class GCPLoadBalancerHandler(BaseHandler):
    def __init__(
            self,
            creds: str | dict | None = None
    ):
        super().__init__()

        # Load credentials from path or dict
        creds = creds or os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
        if isinstance(creds, str):
            credentials: service_account.Credentials = service_account.Credentials.from_service_account_file(
                creds
            )
        elif isinstance(creds, dict):
            credentials: service_account.Credentials = service_account.Credentials.from_service_account_info(
                creds
            )
        else:
            raise ValueError("Invalid credentials: must be a file path or a dictionary.")

        self.credentials = credentials
        self.project_id = credentials.project_id

        # Store credentials for lazy client initialization
        self._client = None
        self.locations = [
            'us-central1', 'us-east1', 'us-east4', 'us-west1', 'us-west2', 'us-west3', 'us-west4',
            'europe-west1', 'europe-west2', 'europe-west3', 'europe-west4', 'europe-west6',
            'europe-central2', 'asia-east1', 'asia-east2', 'asia-northeast1', 'asia-northeast2',
            'asia-northeast3', 'asia-south1', 'asia-southeast1', 'asia-southeast2'
        ]
        self.url_maps_client = compute_v1.UrlMapsClient(credentials=credentials)
        self.backend_services_client = compute_v1.BackendServicesClient(credentials=credentials)
        self.target_http_proxies_client = compute_v1.TargetHttpProxiesClient(credentials=credentials)
        self.target_https_proxies_client = compute_v1.TargetHttpsProxiesClient(credentials=credentials)
        self.global_forwarding_rules_client = compute_v1.GlobalForwardingRulesClient(credentials=credentials)
        self.ssl_certificates_client = compute_v1.SslCertificatesClient(credentials=credentials)
        self.health_checks_client = compute_v1.HealthChecksClient(credentials=credentials)

    @tool
    async def list_all_load_balancer_components(self) -> dict:
        """List all load balancer components concurrently"""
        logger.info("Starting to fetch all load balancer components")

        # Run all API calls concurrently
        results = await asyncio.gather(
            self.get_url_maps(),
            self.get_backend_services(),
            self.get_target_http_proxies(),
            self.get_target_https_proxies(),
            self.get_global_forwarding_rules(),
            self.get_ssl_certificates(),
            self.get_health_checks(),
            return_exceptions=True
        )

        # Process results
        load_balancer_data = {
            'project_id': self.project_id,
            'url_maps': results[0] if not isinstance(results[0], Exception) else [],
            'backend_services': results[1] if not isinstance(results[1], Exception) else [],
            'target_http_proxies': results[2] if not isinstance(results[2], Exception) else [],
            'target_https_proxies': results[3] if not isinstance(results[3], Exception) else [],
            'global_forwarding_rules': results[4] if not isinstance(results[4], Exception) else [],
            'ssl_certificates': results[5] if not isinstance(results[5], Exception) else [],
            'health_checks': results[6] if not isinstance(results[6], Exception) else []
        }

        # Log any exceptions
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                component_names = ['url_maps', 'backend_services', 'target_http_proxies',
                                   'target_https_proxies', 'global_forwarding_rules',
                                   'ssl_certificates', 'health_checks']
                logger.error(f"Error fetching {component_names[i]}: {result}")

        logger.info("Completed fetching all load balancer components")
        return load_balancer_data

    async def get_url_maps(self) -> List[Dict[str, Any]]:
        """Get all URL maps (Application Load Balancers)"""
        logger.info(f"Fetching URL maps for project: {self.project_id}")

        try:
            request = await sync_to_async(compute_v1.ListUrlMapsRequest, project=self.project_id)
            url_maps = []

            async for url_map in iter_to_aiter(self.url_maps_client.list(request=request)):
                url_map_dict = {
                    'name': url_map.name,
                    'id': url_map.id,
                    'creation_timestamp': url_map.creation_timestamp,
                    'description': url_map.description,
                    'self_link': url_map.self_link,
                    'default_service': url_map.default_service,
                    'fingerprint': url_map.fingerprint,
                    'kind': url_map.kind,
                    'host_rules': [],
                    'path_matchers': [],
                    'tests': []
                }

                # Process host rules
                async for host_rule in iter_to_aiter(url_map.host_rules):
                    host_rule_dict = {
                        'hosts': list(host_rule.hosts),
                        'path_matcher': host_rule.path_matcher,
                        'description': host_rule.description
                    }
                    url_map_dict['host_rules'].append(host_rule_dict)

                # Process path matchers
                async for path_matcher in iter_to_aiter(url_map.path_matchers):
                    path_matcher_dict = {
                        'name': path_matcher.name,
                        'description': path_matcher.description,
                        'default_service': path_matcher.default_service,
                        'path_rules': []
                    }

                    async for path_rule in iter_to_aiter(path_matcher.path_rules):
                        path_rule_dict = {
                            'paths': list(path_rule.paths),
                            'service': path_rule.service,
                            'route_action': {}
                        }

                        if hasattr(path_rule, 'route_action') and path_rule.route_action:
                            path_rule_dict['route_action'] = {
                                'weighted_backend_services': [],
                                'url_rewrite': {},
                                'timeout': path_rule.route_action.timeout if hasattr(path_rule.route_action,
                                                                                     'timeout') else None
                            }

                        path_matcher_dict['path_rules'].append(path_rule_dict)

                    url_map_dict['path_matchers'].append(path_matcher_dict)
            return url_maps

        except exceptions.GoogleAPICallError as e:
            logger.error(f"Error fetching URL maps: {e}")
            return []

    async def get_backend_services(self) -> List[Dict[str, Any]]:
        """Get all backend services"""
        logger.info(f"Fetching backend services for project: {self.project_id}")

        try:
            request = await sync_to_async(compute_v1.ListBackendServicesRequest, project=self.project_id)
            backend_services = []

            async for backend_service in iter_to_aiter(self.backend_services_client.list(request=request)):
                backend_service_dict = {
                    'name': backend_service.name,
                    'id': backend_service.id,
                    'creation_timestamp': backend_service.creation_timestamp,
                    'description': backend_service.description,
                    'self_link': backend_service.self_link,
                    'protocol': backend_service.protocol,
                    'port': backend_service.port,
                    'port_name': backend_service.port_name,
                    'timeout_sec': backend_service.timeout_sec,
                    'enable_cdn': backend_service.enable_cdn,
                    'health_checks': list(backend_service.health_checks),
                    'load_balancing_scheme': backend_service.load_balancing_scheme,
                    'session_affinity': backend_service.session_affinity,
                    'affinity_cookie_ttl_sec': backend_service.affinity_cookie_ttl_sec,
                    'connection_draining_timeout_sec': backend_service.connection_draining_timeout_sec,
                    'backends': []
                }

                # Process backends
                async for backend in iter_to_aiter(backend_service.backends):
                    backend_dict = {
                        'group': backend.group,
                        'balancing_mode': backend.balancing_mode,
                        'max_utilization': backend.max_utilization,
                        'max_rate': backend.max_rate,
                        'max_rate_per_instance': backend.max_rate_per_instance,
                        'max_connections': backend.max_connections,
                        'max_connections_per_instance': backend.max_connections_per_instance,
                        'capacity_scaler': backend.capacity_scaler,
                        'description': backend.description
                    }
                    backend_service_dict['backends'].append(backend_dict)

                backend_services.append(backend_service_dict)
            return backend_services

        except exceptions.GoogleAPICallError as e:
            logger.error(f"Error fetching backend services: {e}")
            return []

    async def get_target_http_proxies(self) -> List[Dict[str, Any]]:
        """Get all target HTTP proxies"""
        logger.info(f"Fetching target HTTP proxies for project: {self.project_id}")

        try:
            request = await sync_to_async(compute_v1.ListTargetHttpProxiesRequest, project=self.project_id)
            target_http_proxies = []

            async for proxy in iter_to_aiter(self.target_http_proxies_client.list(request=request)):
                proxy_dict = {
                    'name': proxy.name,
                    'id': proxy.id,
                    'creation_timestamp': proxy.creation_timestamp,
                    'description': proxy.description,
                    'self_link': proxy.self_link,
                    'url_map': proxy.url_map,
                    'kind': proxy.kind,
                    'region': proxy.region if hasattr(proxy, 'region') else None
                }
                target_http_proxies.append(proxy_dict)

            return target_http_proxies

        except exceptions.GoogleAPICallError as e:
            logger.error(f"Error fetching target HTTP proxies: {e}")
            return []

    async def get_target_https_proxies(self) -> List[Dict[str, Any]]:
        """Get all target HTTPS proxies"""
        logger.info(f"Fetching target HTTPS proxies for project: {self.project_id}")

        try:
            request = await sync_to_async(compute_v1.ListTargetHttpsProxiesRequest, project=self.project_id)
            target_https_proxies = []

            async for proxy in iter_to_aiter(self.target_https_proxies_client.list(request=request)):
                proxy_dict = {
                    'name': proxy.name,
                    'id': proxy.id,
                    'creation_timestamp': proxy.creation_timestamp,
                    'description': proxy.description,
                    'self_link': proxy.self_link,
                    'url_map': proxy.url_map,
                    'ssl_certificates': list(proxy.ssl_certificates),
                    'kind': proxy.kind,
                    'region': proxy.region if hasattr(proxy, 'region') else None,
                    'quic_override': proxy.quic_override if hasattr(proxy, 'quic_override') else None
                }
                target_https_proxies.append(proxy_dict)
            return target_https_proxies

        except exceptions.GoogleAPICallError as e:
            logger.error(f"Error fetching target HTTPS proxies: {e}")
            return []

    async def get_global_forwarding_rules(self) -> List[Dict[str, Any]]:
        """Get all global forwarding rules"""
        logger.info(f"Fetching global forwarding rules for project: {self.project_id}")

        try:
            request = await sync_to_async(compute_v1.ListGlobalForwardingRulesRequest, project=self.project_id)
            forwarding_rules = []

            async for rule in iter_to_aiter(self.global_forwarding_rules_client.list(request=request)):
                rule_dict = {
                    'name': rule.name,
                    'id': rule.id,
                    'creation_timestamp': rule.creation_timestamp,
                    'description': rule.description,
                    'self_link': rule.self_link,
                    'ip_address': rule.ip_address,
                    'ip_protocol': rule.ip_protocol,
                    'port_range': rule.port_range,
                    'ports': list(rule.ports),
                    'target': rule.target,
                    'load_balancing_scheme': rule.load_balancing_scheme,
                    'network_tier': rule.network_tier,
                    'kind': rule.kind,
                    'ip_version': rule.ip_version if hasattr(rule, 'ip_version') else None
                }
                forwarding_rules.append(rule_dict)
            return forwarding_rules

        except exceptions.GoogleAPICallError as e:
            logger.error(f"Error fetching global forwarding rules: {e}")
            return []

    async def get_ssl_certificates(self) -> List[Dict[str, Any]]:
        """Get all SSL certificates"""
        logger.info(f"Fetching SSL certificates for project: {self.project_id}")

        try:
            request = await sync_to_async(compute_v1.ListSslCertificatesRequest, project=self.project_id)
            ssl_certificates = []

            async for cert in iter_to_aiter(self.ssl_certificates_client.list(request=request)):
                cert_dict = {
                    'name': cert.name,
                    'id': cert.id,
                    'creation_timestamp': cert.creation_timestamp,
                    'description': cert.description,
                    'self_link': cert.self_link,
                    'certificate': cert.certificate[:100] + "..." if len(cert.certificate) > 100 else cert.certificate,
                    # Truncate for security
                    'private_key': "***REDACTED***" if cert.private_key else None,
                    'expire_time': cert.expire_time if hasattr(cert, 'expire_time') else None,
                    'subject_alternative_names': list(cert.subject_alternative_names),
                    'kind': cert.kind,
                    'type': cert.type_ if hasattr(cert, 'type_') else None
                }
                ssl_certificates.append(cert_dict)
            return ssl_certificates

        except exceptions.GoogleAPICallError as e:
            logger.error(f"Error fetching SSL certificates: {e}")
            return []

    async def get_health_checks(self) -> List[Dict[str, Any]]:
        """Get all health checks"""
        logger.info(f"Fetching health checks for project: {self.project_id}")

        try:
            request = await sync_to_async(compute_v1.ListHealthChecksRequest, project=self.project_id)
            health_checks = []

            async for hc in iter_to_aiter(self.health_checks_client.list(request=request)):
                hc_dict = {
                    'name': hc.name,
                    'id': hc.id,
                    'creation_timestamp': hc.creation_timestamp,
                    'description': hc.description,
                    'self_link': hc.self_link,
                    'check_interval_sec': hc.check_interval_sec,
                    'timeout_sec': hc.timeout_sec,
                    'unhealthy_threshold': hc.unhealthy_threshold,
                    'healthy_threshold': hc.healthy_threshold,
                    'type': hc.type_,
                    'kind': hc.kind
                }

                # Add type-specific properties
                if hasattr(hc, 'http_health_check') and hc.http_health_check:
                    hc_dict['http_health_check'] = {
                        'port': hc.http_health_check.port,
                        'port_name': hc.http_health_check.port_name,
                        'port_specification': hc.http_health_check.port_specification,
                        'host': hc.http_health_check.host,
                        'request_path': hc.http_health_check.request_path,
                        'proxy_header': hc.http_health_check.proxy_header
                    }

                if hasattr(hc, 'https_health_check') and hc.https_health_check:
                    hc_dict['https_health_check'] = {
                        'port': hc.https_health_check.port,
                        'port_name': hc.https_health_check.port_name,
                        'port_specification': hc.https_health_check.port_specification,
                        'host': hc.https_health_check.host,
                        'request_path': hc.https_health_check.request_path,
                        'proxy_header': hc.https_health_check.proxy_header
                    }

                health_checks.append(hc_dict)
            return health_checks

        except exceptions.GoogleAPICallError as e:
            logger.error(f"Error fetching health checks: {e}")
            return []
