import inspect


class DryRun(object):
    """
    Detect dry_run functions and save the associated handler
    """
    def __init__(self):
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

    def register_dry_run_handler(self, module, handler_name, handler_code, dry_run_code):
        self.__entries.append(
            _DryRunEntry(
                target_module=module,
                handler_name=handler_name,
                handler_code=handler_code,
                dry_run_code=dry_run_code
            )
        )

    def dry_run_mode_on(self):
        for entry in self.__entries:
            entry.set()

    def dry_run_mode_off(self):
        for entry in self.__entries:
            entry.unset()

    def dump_entries_stdout(self):
        print "== DryRunManager dump =="
        print "  MODULE:    HANDLER  STATUS"
        for entry in self.__entries:
            print "  %s: %s %s" % (repr(entry.target_module), entry.handler_name, "ON" if entry.get_status() else "OFF")
        print "========================"
