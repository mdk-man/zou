from zou.app.models.asset_instance import AssetInstance

from zou.app.services import assets_service, user_service
from zou.app.utils import permissions

from .base import BaseModelResource, BaseModelsResource


class AssetInstancesResource(BaseModelsResource):

    def __init__(self):
        BaseModelsResource.__init__(self, AssetInstance)


class AssetInstanceResource(BaseModelResource):

    def __init__(self):
        BaseModelResource.__init__(self, AssetInstance)

    def check_read_permissions(self, instance):
        if permissions.has_manager_permissions():
            return True
        else:
            asset_instance = self.get_model_or_404(instance["id"])
            asset = assets_service.get_asset(asset_instance.asset_id)
            return user_service.check_has_task_related(asset["project_id"])

    def check_update_permissions(self, asset_instance, data):
        if permissions.has_manager_permissions():
            return True
        else:
            return user_service.check_working_on_entity(
                asset_instance["entity_id"]
            )