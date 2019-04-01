# -*- mode: python; python-indent: 4 -*-
import ncs
from ncs.application import Service
import resource_manager.id_allocator as id_allocator

# ------------------------
# SERVICE CALLBACK EXAMPLE
# ------------------------
class ServiceCallbacks(Service):

    # The create() callback is invoked inside NCS FASTMAP and
    # must always exist.
    @Service.create
    def cb_create(self, tctx, root, service, proplist):
        self.log.info("Service create(service=", service._path, ")")

        id_allocator.id_request(
            service,
            "/access-python[customer='%s']" % (service.customer),
            tctx.username,
            "vlans",
            service.customer,
            False,
        )
        vlan = id_allocator.id_read(tctx.username, root, "vlans", service.customer)
        if not vlan:
            self.log.info("VLAN not ready")
            return
        service.vlan = vlan

        custom_interface_description = root.location__location[
            service.device
        ].location__address
        self.log.info(
            "custom_interface_description : {}".format(custom_interface_description)
        )
        template_vars = ncs.template.Variables()
        template_vars.add("VLAN", vlan)
        template_vars.add("ACCESS_GE_INTERFACE", service.access_ge_interface)
        template_vars.add("TRUNK_GE_INTERFACE", service.trunk_ge_interface)
        template_vars.add("ACCESS_INT_DESCRIPTION", custom_interface_description)
        template = ncs.template.Template(service)
        template.apply("access-python-template", template_vars)

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
        self.register_service("access-python-servicepoint", ServiceCallbacks)

        # If we registered any callback(s) above, the Application class
        # took care of creating a daemon (related to the service/action point).

        # When this setup method is finished, all registrations are
        # considered done and the application is 'started'.

    def teardown(self):
        # When the application is finished (which would happen if NCS went
        # down, packages were reloaded or some error occurred) this teardown
        # method will be called.

        self.log.info("Main FINISHED")
