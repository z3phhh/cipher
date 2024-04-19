package com.zephhh.controller;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/*

1. Реализовать сервис с тремя серверами следующего характера:
Сервер_1 - сервер на котором задается открытое сообщение, шифруется и передается на Сервер_2. Также открытый ключ передается на Сервер_3.
Сервер_2 - сервер который получает шифрованный текст и логирует его (делаем вид что преступник получил доступ к шифрованному сообщению)
Сервер_3 - сервер на котором происходит расшифрованние шифротекста от Сервер_2, с помощью ключа полученного из Сервер_1.

2. Подписание сообщений с помощью ЭЦП и подтверждение сообщения с помощью ЭЦП

*/

@Slf4j
@RestController
@RequestMapping("/server3")
public class DecryptionController {

    private KeyPair keyPair;

    @PostConstruct
    public void initKeys() {
        this.keyPair = generateKeyPair();
    }

    private KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            log.error("Ошибка при генерации пары ключей", e);
            return null;
        }
    }

    @GetMapping("/publicKey")
    public String getPublicKey() {
        PublicKey publicKey = this.keyPair.getPublic();
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    @PostMapping("/decrypt")
    public ResponseEntity<String> decrypt(@RequestBody String encryptedMessage) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
            String decryptedMessage = new String(decryptedBytes);
            return ResponseEntity.ok("Расшифрованное сообщение: " + decryptedMessage);
        } catch (GeneralSecurityException e) {
            log.error("Ошибка безопасности при расшифровке сообщения", e);
            return ResponseEntity.internalServerError().body("Ошибка безопасности при расшифровке");
        } catch (IllegalArgumentException e) {
            log.error("Некорректные данные или формат ключа", e);
            return ResponseEntity.badRequest().body("Некорректные данные или формат ключа");
        } catch (Exception e) {
            log.error("Произошла ошибка при расшифровке", e);
            return ResponseEntity.internalServerError().body("Неизвестная ошибка при расшифровке");
        }
    }
}