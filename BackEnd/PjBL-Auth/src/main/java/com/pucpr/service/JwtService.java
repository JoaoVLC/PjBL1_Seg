package com.pucpr.service;

import com.pucpr.model.Usuario;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.util.Date;

public class JwtService {

    // A chave vem de variavel de ambiente para nao ficar salva no codigo.
    // Para HS256, ela precisa ter pelo menos 32 caracteres.
    private static final String ENV_SECRET_NAME = "JWT_SECRET";
    private static final long EXPIRATION_MILLIS = 15 * 60 * 1000; // 15 minutos

    private SecretKey getSigningKey() {
        String secret = System.getenv(ENV_SECRET_NAME);

        // Falhamos cedo com uma mensagem clara caso a variavel nao tenha sido configurada.
        if (secret == null || secret.length() < 32) {
            throw new IllegalStateException("Configure a variavel JWT_SECRET com pelo menos 32 caracteres.");
        }

        return Keys.hmacShaKeyFor(secret.getBytes());
    }

    /**
     * Gera um token assinado com e-mail, role, data de emissao e expiracao.
     */
    public String generateToken(Usuario user) {
        Date agora = new Date();
        Date expiracao = new Date(System.currentTimeMillis() + EXPIRATION_MILLIS);

        return Jwts.builder()
                .subject(user.getEmail())
                .claim("role", user.getRole())
                .issuedAt(agora)
                .expiration(expiracao)
                .signWith(getSigningKey())
                .compact();
    }

    /**
     * Extrai o e-mail do token depois de validar a assinatura.
     */
    public String extractEmail(String token) {
        // parseSignedClaims valida a assinatura antes de liberar os dados do payload.
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    /**
     * Valida se o token e autentico e se ainda nao expirou.
     */
    public boolean validateToken(String token) {
        try {
            // Se estiver expirado, adulterado ou assinado com outra chave, esta linha lanca excecao.
            Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (Exception e) {
            System.out.println("Token invalido: " + e.getMessage());
            return false;
        }
    }
}
