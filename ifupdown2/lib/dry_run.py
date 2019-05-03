import inspect


class DryRun(object):
    """
    Detect dry_run functions and save the associated handler
    """
    def __init__(self):
        # disabling DryRun as it's creating a huge memory leak in daemon mode
        # this needs to be fixed before re-enabling dryruns
        # context: in daemon mode, each time we create an object with DryRun
        # inheritance, a reference to this object and its code is added to the
        # DryRunManager via DryRunEntry and stored in a list
        # DryRunManager:__entries, this list keeps growing and keeps refs to
        # objects that should be collected by the garbage collector.
        # A potential fix would be to have a dictionary to store those entries
        # instead of a list, something like:
        # {
        #   "module": {
        #       "base_attr_name": {
        #           base_attr_value: attr_value
        #       }
        # }
        # This needs to be studied a bit longer...
        #
        # Also the destructor of each objects should make sure to remove it's
        # DryRunEntries from the dict when the object is removed?
        # -> Not sure this would work... Since many objects of the same type
        # can exists at the same time
        #
        # It's probably fine to keep a dictionary (without duplicates)
        # of all the module and dry_run entries.
        # Once a new object is created (with DryRun inheritance) we can look
        # in this "cache" to see if we already have an existing dryrun entry
        # and re-use this one.
        for attr_name in dir(self):
            try:
                # We need to iterate through the object attribute
                # to find dryrun methods
                if attr_name.lower().endswith("_dry_run"):
                    attr_value = getattr(self, attr_name)

                    # When we find a dryrun attribute we need to make sure
                    # it is a callable function or method.
                    if not self.__is_method_or_function(attr_value):
                        continue

                    base_attr_name = attr_name[:-8]
                    base_attr_value = getattr(self, base_attr_name)
                    # We try infere the base method/function name
                    # then make sure its a function or method
                    if not self.__is_method_or_function(base_attr_value):
                        continue

                    # now we are pretty sure we have want we want:
                    # - the base function
                    # - the associated dry_run code
                    # we will now register this couple in the DryRunManager
                    DryRunManager.get_instance().register_dry_run_handler(
                        self,
                        handler_name=base_attr_name,
                        handler_code=base_attr_value,
                        dry_run_code=attr_value
                    )
            except:
                pass

    @staticmethod
    def __is_method_or_function(obj):
        return callable(obj) and (inspect.ismethod(obj) or inspect.isfunction(obj))


class _DryRunEntry(object):
    def __init__(self, target_module, handler_name, handler_code, dry_run_code):
        self.target_module = target_module
        self.handler_name = handler_name
        self.handler_code = handler_code
        self.dry_run_code = dry_run_code
        self.__status = False

    def set(self):
        self.target_module.__dict__[self.handler_name] = self.dry_run_code
        self.__status = True

    def unset(self):
        self.target_module.__dict__[self.handler_name] = self.handler_code
        self.__status = False

    def get_status(self):
        return self.__status


class DryRunManager(object):
    __instance = None

    @staticmethod
    def get_instance():
        if not DryRunManager.__instance:
            DryRunManager.__instance = DryRunManager()
        return DryRunManager.__instance

    def __init__(self):
        if DryRunManager.__instance:
            raise RuntimeError("DryRunManager: invalid access. Please use DryRunManager.getInstance()")
        else:
            DryRunManager.__instance = self

        self.__entries = list()
        self.__is_on = False

    def register_dry_run_handler(self, module, handler_name, handler_code, dry_run_code):
        dry_run_entry = _DryRunEntry(
            target_module=module,
            handler_name=handler_name,
            handler_code=handler_code,
            dry_run_code=dry_run_code
        )
        if self.__is_on:
            dry_run_entry.set()
        self.__entries.append(dry_run_entry)

    def dry_run_mode_on(self):
        """
        Enable the dry run mode
        WARNING: not thread-safe
        """
        for entry in self.__entries:
            entry.set()
        self.__is_on = True

    def dry_run_mode_off(self):
        """
        Disable the dry run mode
        WARNING: not thread-safe
        """
        for entry in self.__entries:
            entry.unset()
        self.__is_on = False

    def dump_entries_stdout(self):
        print "== DryRunManager dump =="
        print "  MODULE:    HANDLER  STATUS"
        for entry in self.__entries:
            print "  %s: %s %s" % (repr(entry.target_module), entry.handler_name, "ON" if entry.get_status() else "OFF")
        print "========================"

    def is_dry_mode_on(self):
        return self.__is_on
