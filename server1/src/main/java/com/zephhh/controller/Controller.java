package com.zephhh.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/server1")
public class Controller {

    private final RestTemplate restTemplate;

    @PostMapping("/send")
    public ResponseEntity<String> encryptAndSend(@RequestBody String message) {
        try {
            ResponseEntity<String> response = restTemplate.getForEntity("http://localhost:8082/server3/publicKey", String.class);
            PublicKey publicKey = convertToPublicKey(response.getBody());

            String encryptedMessage = encrypt(message, publicKey);
            restTemplate.postForEntity("http://localhost:8081/server2/encrypted", encryptedMessage, String.class);

            return ResponseEntity.ok("Сообщение зашифровано и отправлено");
        } catch (Exception e) {
            log.error("Ошибка при шифровании или отправке сообщения", e);
            return ResponseEntity.internalServerError().body("Ошибка при шифровании или отправке");
        }
    }

    private PublicKey convertToPublicKey(String publicKeyEncoded) throws Exception {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyEncoded));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    private String encrypt(String message, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes()));
    }
}
