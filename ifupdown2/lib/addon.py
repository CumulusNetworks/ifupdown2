import logging

try:
    import ifupdown2.lib.nlcache as nlcache

    from ifupdown2.lib.dry_run import DryRun
except ImportError:
    import lib.nlcache as nlcache

    from lib.dry_run import DryRun


class Addon(DryRun):
    """
    Base class for ifupdown addon modules
    Provides common infrastructure methods for all addon modules
    """

    def __init__(self):
        DryRun.__init__(self)

        self.logger = logging.getLogger('ifupdown2.%s' % self.__class__.__name__)

        netlink = nlcache.get_netlink_listener_with_cache()

        self.netlink = netlink
        self.cache = netlink.cache
