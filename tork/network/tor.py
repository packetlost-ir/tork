from stem.control import Controller
from tork.config import CONTROL_PORT

def get_controller() -> Controller:
    controller = Controller.from_port(port=CONTROL_PORT)
    controller.authenticate()
    return controller

def create_onion_service(
    controller: Controller,
    local_port: int,
    key_type: str = "NEW",
    key_content: str = "ED25519-V3",
    await_publication: bool = True
) -> tuple[str, str, str]:
    response = controller.create_ephemeral_hidden_service(
        {80: local_port},
        await_publication=await_publication,
        key_type=key_type,
        key_content=key_content,
        discard_key=False
    )
    service_id = response.service_id
    if service_id.endswith(".onion"):
        service_id = service_id[:-6]
    return service_id, response.private_key_type, response.private_key

def destroy_onion_service(controller: Controller, onion_address: str) -> None:
    service_id = onion_address
    if service_id.endswith(".onion"):
        service_id = service_id[:-6]
    try:
        controller.remove_ephemeral_hidden_service(service_id)
    except Exception:
        pass
