from gidra import proto
from gidra.proxy import GenshinProxy, HandlerRouter, PacketDirection
from gidra.proxy.cmdids import CmdID
from gidra.mhycrypt import encrypt_and_sign, decrypt, new_key

import base64

router = HandlerRouter()

@router(CmdID.GetPlayerTokenReq, PacketDirection.Client)
def handle_token_req(proxy: GenshinProxy, msg: proto.GetPlayerTokenReq):
    client_seed_bytes = decrypt(base64.b64decode(msg.client_rand_key), "SigningKey")

    encrypted_data, _ = encrypt_and_sign(client_seed_bytes, "MHYSignOS1" if (msg.key_id == 5) else "MHYSignCN1")
    msg.client_rand_key = base64.b64encode(encrypted_data).decode()

    proxy.client_seed = int.from_bytes(client_seed_bytes, byteorder='big', signed=False)
    proxy.send(msg, PacketDirection.Server)

@router(CmdID.GetPlayerTokenRsp, PacketDirection.Server)
def handle_token_rsp(proxy: GenshinProxy, msg: proto.GetPlayerTokenRsp):
    server_seed_bytes = decrypt(base64.b64decode(msg.server_rand_key), msg.key_id)
    server_seed = int.from_bytes(server_seed_bytes, byteorder='big', signed=False)

    seed = server_seed ^ proxy.client_seed

    _, sign = encrypt_and_sign(server_seed_bytes, msg.key_id)
    msg.sign = base64.b64encode(sign).decode()

    proxy.send(msg, PacketDirection.Client)
    proxy.key = new_key(seed)