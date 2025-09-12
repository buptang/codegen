    def _perform_handshake(self) -> bool:
        """执行完整的DTLS握手流程，包括Hello Verify Request处理"""
        try:
            # 第一阶段：发送初始Client Hello (无Cookie)
            logger.info("1. 发送初始Client Hello (无Cookie)")
            client_hello = self.create_client_hello()
            client_hello_record = self.record_layer.create_record(
                DTLSConstants.HANDSHAKE, client_hello)
            self.socket.send(client_hello_record)
            
            # 接收响应 - 应该是Hello Verify Request
            logger.info("2. 等待Hello Verify Request")
            response = self.socket.recv(4096)
            content_type, payload = self.record_layer.parse_record(response)
            
            if content_type != DTLSConstants.HANDSHAKE:
                logger.error("期望握手消息，收到其他类型")
                return False
            
            msg_type, message_data = self.handshake_layer.parse_handshake_message(payload)
            
            # 检查是否收到Hello Verify Request
            if msg_type == DTLSConstants.HELLO_VERIFY_REQUEST:
                logger.info("收到Hello Verify Request，解析Cookie")
                if not self.parse_hello_verify_request(message_data):
                    return False
                
                # 第二阶段：发送带Cookie的Client Hello
                logger.info("3. 发送带Cookie的Client Hello")
                client_hello_with_cookie = self.create_client_hello()
                client_hello_record = self.record_layer.create_record(
                    DTLSConstants.HANDSHAKE, client_hello_with_cookie)
                self.socket.send(client_hello_record)
                
                # 接收Server Hello
                logger.info("4. 等待Server Hello")
                response = self.socket.recv(4096)
                content_type, payload = self.record_layer.parse_record(response)
                
                if content_type != DTLSConstants.HANDSHAKE:
                    logger.error("期望握手消息，收到其他类型")
                    return False
                
                msg_type, server_hello_data = self.handshake_layer.parse_handshake_message(payload)
                if msg_type != DTLSConstants.SERVER_HELLO:
                    logger.error("期望Server Hello消息")
                    return False
                    
            elif msg_type == DTLSConstants.SERVER_HELLO:
                # 服务器直接发送Server Hello (可能不支持Hello Verify Request)
                logger.warning("服务器跳过了Hello Verify Request，直接发送Server Hello")
                server_hello_data = message_data
            else:
                logger.error(f"收到意外的握手消息类型: {msg_type}")
                return False
            
            # 解析Server Hello
            if not self.parse_server_hello(server_hello_data):
                return False
            
            # 5. 接收Certificate (可选)
            logger.info("5. 等待Certificate")
            try:
                response = self.socket.recv(4096)
                content_type, payload = self.record_layer.parse_record(response)
                
                if content_type == DTLSConstants.HANDSHAKE:
                    msg_type, cert_data = self.handshake_layer.parse_handshake_message(payload)
                    if msg_type == DTLSConstants.CERTIFICATE:
                        self.parse_certificate(cert_data)
            except socket.timeout:
                logger.info("未收到证书消息（可能是PSK模式）")
            
            # 6. 接收Server Hello Done
            logger.info("6. 等待Server Hello Done")
            try:
                response = self.socket.recv(4096)
                content_type, payload = self.record_layer.parse_record(response)
                
                if content_type == DTLSConstants.HANDSHAKE:
                    msg_type, _ = self.handshake_layer.parse_handshake_message(payload)
                    if msg_type != DTLSConstants.SERVER_HELLO_DONE:
                        logger.warning("未收到Server Hello Done")
            except socket.timeout:
                logger.info("未收到Server Hello Done（继续握手）")
            
            # 7. 发送Client Key Exchange
            logger.info("7. 发送Client Key Exchange")
            client_key_exchange = self.create_client_key_exchange()
            if client_key_exchange:
                client_key_exchange_record = self.record_layer.create_record(
                    DTLSConstants.HANDSHAKE, client_key_exchange)
                self.socket.send(client_key_exchange_record)
            
            # 8. 发送Change Cipher Spec
            logger.info("8. 发送Change Cipher Spec")
            change_cipher_spec = struct.pack('!B', 1)
            change_cipher_spec_record = self.record_layer.create_record(
                DTLSConstants.CHANGE_CIPHER_SPEC, change_cipher_spec)
            self.socket.send(change_cipher_spec_record)
            
            # 9. 发送Finished
            logger.info("9. 发送Finished")
            finished = self.create_finished_message()
            finished_record = self.record_layer.create_record(
                DTLSConstants.HANDSHAKE, finished)
            self.socket.send(finished_record)
            
            # 10. 接收Change Cipher Spec
            logger.info("10. 等待Change Cipher Spec")
            try:
                response = self.socket.recv(4096)
                content_type, payload = self.record_layer.parse_record(response)
                if content_type == DTLSConstants.CHANGE_CIPHER_SPEC:
                    logger.info("收到Change Cipher Spec")
            except socket.timeout:
                logger.warning("未收到Change Cipher Spec")
            
            # 11. 接收Finished
            logger.info("11. 等待Finished")
            try:
                response = self.socket.recv(4096)
                content_type, payload = self.record_layer.parse_record(response)
                if content_type == DTLSConstants.HANDSHAKE:
                    msg_type, finished_data = self.handshake_layer.parse_handshake_message(payload)
                    if msg_type == DTLSConstants.FINISHED:
                        logger.info("收到Finished消息")
                        if self.verify_finished_message(finished_data):
                            logger.info("Finished消息验证成功")
                        else:
                            logger.warning("Finished消息验证失败")
            except socket.timeout:
                logger.warning("未收到Finished消息")
            
            logger.info("DTLS握手完成")
            return True
            
        except Exception as e:
            logger.error(f"握手过程中发生错误: {e}")
            return False

