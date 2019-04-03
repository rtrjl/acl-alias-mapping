# -*- mode: python; python-indent: 4 -*-
import ncs, re
from ncs.dp import Action


# ------------------------
# SERVICE CALLBACK EXAMPLE
# ------------------------
class ServiceCallbacks(Action):

    # The create() callback is invoked inside NCS FASTMAP and
    # must always exist.
    @Action.action
    def cb_action(self, uinfo, name, kp, input, output):
        with ncs.maapi.Maapi() as m:
            with ncs.maapi.Session(m, "admin", "python"):
                with m.start_write_trans() as t:
                    root = ncs.maagic.get_root(t)
                    device = root.devices.device[input.device]
                    input_test = device.config.ios__EXEC["exec"].get_input()
                    input_test.args = ["access-list 199 permit tcp any any eq ?"]
                    result_test = device.config.ios__EXEC["exec"](input_test)
                    # todo put

                    regex = r"^\s+(\S+)\s+.+\((\d+)"
                    matches = re.finditer(regex, result_test.result, re.MULTILINE)
                    output.acl_maping.create()
                    for match in matches:
                        my_acl = output.acl_maping.create(int(match.group(2)))
                        my_acl.protocol = match.group(1)
                    t.apply()

    # The pre_modification() and post_modification() callbacks are optional,
    # and are invoked outside FASTMAP. pre_modification() is invoked before
    # create, update, or delete of the service, as indicated by the enum
    # ncs_service_operation op parameter. Conversely
    # post_modification() is invoked after create, update, or delete
    # of the service. These functions can be useful e.g. for
    # allocations that should be stored and existing also when the
    # service instance is removed.

    # @Service.pre_lock_create
    # def cb_pre_lock_create(self, tctx, root, service, proplist):
    #     self.log.info('Service plcreate(service=', service._path, ')')

    # @Service.pre_modification
    # def cb_pre_modification(self, tctx, op, kp, root, proplist):
    #     self.log.info('Service premod(service=', kp, ')')

    # @Service.post_modification
    # def cb_post_modification(self, tctx, op, kp, root, proplist):
    #     self.log.info('Service premod(service=', kp, ')')


# ---------------------------------------------
# COMPONENT THREAD THAT WILL BE STARTED BY NCS.
# ---------------------------------------------
class Main(ncs.application.Application):
    def setup(self):
        # The application class sets up logging for us. It is accessible
        # through 'self.log' and is a ncs.log.Log instance.
        self.log.info("Main RUNNING")

        # Service callbacks require a registration for a 'service point',
        # as specified in the corresponding data model.
        #
        self.register_action("acl-alias-mapping", ServiceCallbacks)

        # If we registered any callback(s) above, the Application class
        # took care of creating a daemon (related to the service/action point).

        # When this setup method is finished, all registrations are
        # considered done and the application is 'started'.

    def teardown(self):
        # When the application is finished (which would happen if NCS went
        # down, packages were reloaded or some error occurred) this teardown
        # method will be called.

        self.log.info("Main FINISHED")