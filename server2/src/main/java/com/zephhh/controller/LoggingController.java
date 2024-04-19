package com.zephhh.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/server2")
public class LoggingController {

    @PostMapping("/encrypted")
    public ResponseEntity<String> logEncryptedMessage(@RequestBody String encryptedMessage) {
        log.info("Получено зашифрованное сообщение: {}", encryptedMessage);
        return ResponseEntity.ok("Сообщение получено и залогировано");
    }
}