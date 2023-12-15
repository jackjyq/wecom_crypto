from unittest import TestCase

from wecom_crypto import WecomCrypto, WecomMessage


class TestWecomCrypto(TestCase):
    crypto = WecomCrypto(
        token="hJqcu3uJ9Tn2gXPmxx2w9kkCkCE2EPYo",
        encoding_aes_key="6qkdMrq68nTKduznJYO1A37W2oEgpkMUvkttRToqhUt",
        receive_id="ww1436e0e65a779aee",
    )
    xml_text = "<xml><ToUserName><![CDATA[ww1436e0e65a779aee]]></ToUserName><Encrypt><![CDATA[Kl7kjoSf6DMD1zh7rtrHjFaDapSCkaOnwu3bqLc5tAybhhMl9pFeK8NslNPVdMwmBQTNoW4mY7AIjeLvEl3NyeTkAgGzBhzTtRLNshw2AEew+kkYcD+Fq72Kt00fT0WnN87hGrW8SqGc+NcT3mu87Ha3dz1pSDi6GaUA6A0sqfde0VJPQbZ9U+3JWcoD4Z5jaU0y9GSh010wsHF8KZD24YhmZH4ch4Ka7ilEbjbfvhKkNL65HHL0J6EYJIZUC2pFrdkJ7MhmEbU2qARR4iQHE7wy24qy0cRX3Mfp6iELcDNfSsPGjUQVDGxQDCWjayJOpcwocugux082f49HKYg84EpHSGXAyh+/oxwaWbvL6aSDPOYuPDGOCI8jmnKiypE+]]></Encrypt><AgentID><![CDATA[1000002]]></AgentID></xml>"
    message = WecomMessage(
        to_user_name="ww1436e0e65a779aee",
        from_user_name="ChenJiaShun",
        create_time="1476422779",
        msg_type="text",
        msg_id="1456453720",
        agent_id="1000002",
        content="你好",
    )

    def test_verify_url(self):
        self.assertEqual(
            self.crypto.verify_url(
                msg_signature="012bc692d0a58dd4b10f8dfe5c4ac00ae211ebeb",
                timestamp="1476416373",
                nonce="47744683",
                echostr="fsi1xnbH4yQh0+PJxcOdhhK6TDXkjMyhEPA7xB2TGz6b+g7xyAbEkRxN/3cNXW9qdqjnoVzEtpbhnFyq6SVHyA==",
            ),
            "1288432023552776189",
        )

    def test_decrypt_message(self):
        self.assertEqual(
            self.crypto.decrypt_message(
                xml_text=self.xml_text,
                msg_signature="0c3914025cb4b4d68103f6bfc8db550f79dcf48e",
                timestamp="1476422779",
                nonce="1597212914",
            ),
            self.message,
        )

    def test_encrypt_message(self):
        encrypted_msg = self.crypto.encrypt_message(
            xml_text="<xml><ToUserName>ww1436e0e65a779aee</ToUserName><FromUserName>ChenJiaShun</FromUserName><CreateTime>1476422779</CreateTime><MsgType>text</MsgType><Content>你好</Content><MsgId>1456453720</MsgId><AgentID>1000002</AgentID></xml>",
            timestamp="1476422779",
            nonce="1597212914",
        )

        self.assertEqual(
            self.crypto.decrypt_message(
                xml_text=encrypted_msg,
                timestamp="1476422779",
                nonce="1597212914",
            ),
            self.message,
        )
