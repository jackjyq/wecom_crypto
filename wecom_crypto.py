import base64
import hashlib
import socket
import struct
import time
import xml.etree.cElementTree as ET
from dataclasses import dataclass
from enum import IntEnum

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class WecomError(IntEnum):
    """加解密库的返回码

    Refs:
        https://developer.work.weixin.qq.com/devtool/introduce?id=10128
    """

    WecomCrypto_ValidateSignature_Error = -40001
    WecomCrypto_Parse_Error = -40002
    WecomCrypto_ComputeSignature_Error = -40003
    WecomCrypto_IllegalAesKey = -40004
    WecomCrypto_ValidateCorpid_Error = -40005
    WecomCrypto_EncryptAES_Error = -40006
    WecomCrypto_DecryptAES_Error = -40007
    WecomCrypto_IllegalBuffer = -40008
    WecomCrypto_EncodeBase64_Error = -40009
    WecomCrypto_DecodeBase64_Error = -40010
    WecomCrypto_GenReturnXml_Error = -40011


class WecomCryptoError(Exception):
    def __init__(self, message, error: WecomError) -> None:
        super().__init__(message)
        self.error_code = error


@dataclass
class WecomMessage:
    """接收到的消息格式

    Refs:
        https://developer.work.weixin.qq.com/document/path/90239
    """

    # 通用
    to_user_name: str | None = None
    from_user_name: str | None = None
    create_time: str | None = None
    msg_type: str | None = None
    msg_id: str | None = None
    agent_id: str | None = None
    # 文本消息
    content: str | None = None
    # 图片消息
    pic_url: str | None = None
    # 语音消息
    media_id: str | None = None
    format: str | None = None
    # 视频消息
    thumb_media_id: str | None = None
    # 位置消息
    location_x: str | None = None
    location_y: str | None = None
    scale: str | None = None
    label: str | None = None
    app_type: str | None = None
    # 链接消息
    title: str | None = None
    description: str | None = None
    url: str | None = None


class XMLParser:
    @staticmethod
    def extract_encrypt_text(xml: str) -> str:
        """提取出xml数据包中的加密消息"""
        try:
            xml_tree = ET.fromstring(xml)
        except ET.ParseError as e:
            raise WecomCryptoError(message=e, error=WecomError.WecomCrypto_Parse_Error)

        if (element := xml_tree.find("Encrypt")) is None or element.text is None:
            raise WecomCryptoError(
                message="encrypt text not found",
                error=WecomError.WecomCrypto_Parse_Error,
            )

        return element.text

    @staticmethod
    def construct_received_message(xml: str) -> WecomMessage:
        def get_content(root: ET.Element, path: str) -> str | None:
            element = root.find(path)
            return None if element is None else element.text

        try:
            xml_tree = ET.fromstring(xml)
        except ET.ParseError as e:
            raise WecomCryptoError(
                message=e, error=WecomError.WecomCrypto_GenReturnXml_Error
            )

        return WecomMessage(
            to_user_name=get_content(xml_tree, "ToUserName"),
            from_user_name=get_content(xml_tree, "FromUserName"),
            create_time=get_content(xml_tree, "CreateTime"),
            msg_type=get_content(xml_tree, "MsgType"),
            msg_id=get_content(xml_tree, "MsgId"),
            agent_id=get_content(xml_tree, "AgentID"),
            content=get_content(xml_tree, "Content"),
            pic_url=get_content(xml_tree, "PicUrl"),
            media_id=get_content(xml_tree, "MediaId"),
            format=get_content(xml_tree, "Format"),
            thumb_media_id=get_content(xml_tree, "ThumbMediaId"),
            location_x=get_content(xml_tree, "Location_X"),
            location_y=get_content(xml_tree, "Location_Y"),
            scale=get_content(xml_tree, "Scale"),
            label=get_content(xml_tree, "Label"),
            title=get_content(xml_tree, "Title"),
            description=get_content(xml_tree, "Description"),
            url=get_content(xml_tree, "Url"),
        )

    @staticmethod
    def generate_xml(
        *, encrypted_msg: str, signature: str, timestamp: str, nonce: str
    ) -> str:
        return f"""<xml>
<Encrypt><![CDATA[{encrypted_msg}]]></Encrypt>
<MsgSignature><![CDATA[{signature}]]></MsgSignature>
<TimeStamp>{timestamp}</TimeStamp>
<Nonce><![CDATA[{nonce}]]></Nonce>
</xml>"""


class PKCS7Encoder:
    """提供基于PKCS7算法的加解密接口"""

    block_size = 32

    def encode(self, text):
        """对需要加密的明文进行填充补位
        @param text: 需要进行填充补位操作的明文
        @return: 补齐明文字符串
        """
        text_length = len(text)
        # 计算需要填充的位数
        amount_to_pad = self.block_size - (text_length % self.block_size)
        if amount_to_pad == 0:
            amount_to_pad = self.block_size
        # 获得补位所用的字符
        pad = chr(amount_to_pad)
        return text + (pad * amount_to_pad).encode()

    def decode(self, decrypted):
        """删除解密后明文的补位字符
        @param decrypted: 解密后的明文
        @return: 删除补位字符后的明文
        """
        pad = ord(decrypted[-1])
        if pad < 1 or pad > 32:
            pad = 0
        return decrypted[:-pad]


class AesCrypto(object):
    def __init__(self, key):
        self._key = key

    def encrypt(self, text, receive_id) -> str:
        """对明文进行加密"""
        # 16位随机字符串添加到明文开头
        text = text.encode()
        text = (
            get_random_bytes(16)
            + struct.pack("I", socket.htonl(len(text)))
            + text
            + receive_id.encode()
        )

        # 使用自定义的填充方式对明文进行补位填充
        pkcs7 = PKCS7Encoder()
        text = pkcs7.encode(text)
        # 加密
        try:
            cipher = AES.new(self._key, AES.MODE_CBC, self._key[:16])
            ciphertext = cipher.encrypt(text)
            # 使用BASE64对加密后的字符串进行编码
            return base64.b64encode(ciphertext).decode("utf8")
        except Exception as e:
            raise WecomCryptoError(
                message=e, error=WecomError.WecomCrypto_EncryptAES_Error
            )

    def decrypt(self, encrypted_text, receive_id) -> str:
        """对解密后的明文进行补位删除"""
        try:
            # 使用BASE64对密文进行解码，然后AES-CBC解密
            cipher = AES.new(self._key, AES.MODE_CBC, self._key[:16])
            plain_text = cipher.decrypt(base64.b64decode(encrypted_text))
        except Exception as e:
            raise WecomCryptoError(
                message=e, error=WecomError.WecomCrypto_DecryptAES_Error
            )

        try:
            pad = plain_text[-1]
            # 去掉补位字符串
            # pkcs7 = PKCS7Encoder()
            # plain_text = pkcs7.encode(plain_text)
            # 去除16位随机字符串
            content = plain_text[16:-pad]
            length = socket.ntohl(struct.unpack("I", content[:4])[0])
            decrypted_text = content[4 : length + 4]
            from_receiveid = content[length + 4 :]
        except Exception as e:
            raise WecomCryptoError(
                message=e, error=WecomError.WecomCrypto_IllegalBuffer
            )

        if from_receiveid.decode("utf8") != receive_id:
            raise WecomCryptoError(
                message="receiveid mismatch",
                error=WecomError.WecomCrypto_ValidateCorpid_Error,
            )
        return decrypted_text.decode("utf8")


class WecomCrypto:
    def __init__(self, *, token: str, encoding_aes_key: str, receive_id: str) -> None:
        """以下参数在企业微信管理后台获取,如下：
            https://work.weixin.qq.com/wework_admin

        token, encoding_aes_key：
            “应用管理” -> “应用” -> “自建” -> 点进某个应用 -> "接收消息" -> "API 接收"，用于消息验证与加密

        receive_id：
            加解密库里，ReceiveId 在各个场景的含义不同：
                - 企业应用的回调，表示corpid
                    - "我的企业" -> "企业 ID"
                    - 参考 https://developer.work.weixin.qq.com/document/path/90665#corpid
                - 第三方事件的回调，表示suiteid
                - 个人主体的第三方应用的回调，ReceiveId是一个空字符串
        """
        key = base64.b64decode(encoding_aes_key + "=")
        assert len(key) == 32, "invalid encoding_aes_key"

        self._aes_crypto = AesCrypto(key)
        self._token = token
        self._received_id = receive_id

    ################################ private methods ###################################
    def _get_signature(self, timestamp: str, nonce: str, msg_encrypt: str) -> str:
        """用SHA1算法生成安全签名"""
        sha = hashlib.sha1()
        try:
            sha.update(
                "".join(sorted([self._token, timestamp, nonce, msg_encrypt])).encode()
            )
            return sha.hexdigest()
        except Exception as e:
            raise WecomCryptoError(
                message=e, error=WecomError.WecomCrypto_ComputeSignature_Error
            )

    ################################ public methods ####################################
    def verify_url(
        self, *, msg_signature: str, timestamp: str, nonce: str, echostr: str
    ) -> str:
        """验证URL函数

        Returns:
            验证成功返回解密后的echostr

        Raises:
            WecomCryptoError: 验证失败
        """
        if self._get_signature(timestamp, nonce, echostr) != msg_signature:
            raise WecomCryptoError(
                message="signature mismatch",
                error=WecomError.WecomCrypto_ValidateSignature_Error,
            )

        return self._aes_crypto.decrypt(echostr, self._received_id)

    def encrypt_message(self, xml_text: str, nonce: str, timestamp: str | None = None):
        if timestamp is None:
            timestamp = str(int(time.time()))

        encrypted_msg = self._aes_crypto.encrypt(xml_text, self._received_id)
        signature = self._get_signature(timestamp, nonce, encrypted_msg)

        return XMLParser.generate_xml(
            encrypted_msg=encrypted_msg,
            signature=signature,
            timestamp=timestamp,
            nonce=nonce,
        )

    def decrypt_message(
        self,
        *,
        xml_text: str,
        timestamp: str,
        nonce: str,
        msg_signature: str | None = None,
    ) -> WecomMessage:
        encrypted_text = XMLParser.extract_encrypt_text(xml_text)

        if msg_signature and (
            self._get_signature(timestamp, nonce, encrypted_text) != msg_signature
        ):
            raise WecomCryptoError(
                message="signature mismatch",
                error=WecomError.WecomCrypto_ValidateSignature_Error,
            )

        decrypted_text = self._aes_crypto.decrypt(encrypted_text, self._received_id)

        return XMLParser.construct_received_message(decrypted_text)
