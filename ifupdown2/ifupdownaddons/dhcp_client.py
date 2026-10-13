import logging

try:
    from ifupdown2.ifupdownaddons.dhclient import dhclient
    from ifupdown2.ifupdownaddons.dhcpcd import DhcpcdClient
    from ifupdown2.ifupdown.exceptions import NoDhcpClientAvailable
except (ImportError, ModuleNotFoundError):
    from ifupdownaddons.dhclient import dhclient
    from ifupdownaddons.dhcpcd import DhcpcdClient
    from ifupdown.exceptions import NoDhcpClientAvailable


class DhcpClient:
    """
    Automatically selects an available DHCP client (preferring dhcpcd over dhclient)
    and forwards all method calls to the respective DHCP client.
    """

    impl: DhcpcdClient | dhclient

    _PROXIED_METHODS = [
        'is_running',
        'is_running6',
        'start',
        'start6',
        'stop',
        'stop6',
        'release',
        'release6',
    ]

    def __init__(self, *args, **kwargs):
        self.logger = logging.getLogger('ifupdown.dhcp_client')

        try:
            self.impl = DhcpcdClient(**kwargs)
            self.logger.info('using dhcpcd client')
        except RuntimeError:
            self.logger.debug('dhcpcd client unavailable, trying deprecated dhclient')
            try:
                self.impl = dhclient(**kwargs)
                self.logger.info('using deprecated dhclient client')
            except RuntimeError:
                raise NoDhcpClientAvailable('neither dhcpcd nor dhclient executable found')

    def __getattr__(self, name):
        if name in self._PROXIED_METHODS:
            return getattr(self.impl, name)
        raise AttributeError
