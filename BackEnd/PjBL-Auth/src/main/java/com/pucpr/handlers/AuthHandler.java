package com.pucpr.handlers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pucpr.model.Usuario;
import com.pucpr.repository.UsuarioRepository;
import com.pucpr.service.JwtService;
import com.sun.net.httpserver.HttpExchange;
import org.mindrot.jbcrypt.BCrypt;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;

/**
 * Classe responsavel por gerenciar as requisicoes de autenticacao.
 * Ela faz o papel de Controller: recebe HTTP, chama Repository/Service e devolve JSON.
 */
public class AuthHandler {
    private final UsuarioRepository repository;
    private final JwtService jwtService;
    private final ObjectMapper mapper = new ObjectMapper();

    public AuthHandler(UsuarioRepository repository, JwtService jwtService) {
        this.repository = repository;
        this.jwtService = jwtService;
    }

    /**
     * Gerencia o processo de login.
     * Se e-mail e senha estiverem corretos, devolve um JWT.
     */
    public void handleLogin(HttpExchange exchange) throws IOException {
        addCorsHeaders(exchange);
        if (handleOptions(exchange)) return;

        // Login deve ser POST porque a senha vai no corpo da requisicao, nao na URL.
        if (!"POST".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }

        try {
            // Jackson transforma o JSON recebido em um objeto Java simples.
            LoginRequest request = mapper.readValue(exchange.getRequestBody(), LoginRequest.class);
            Optional<Usuario> usuarioEncontrado = repository.findByEmail(request.email);

            // Mensagem generica: nao revelamos se o e-mail existe ou se a senha errou.
            if (usuarioEncontrado.isEmpty()) {
                sendJson(exchange, 401, Map.of("message", "E-mail ou senha invalidos."));
                return;
            }

            Usuario usuario = usuarioEncontrado.get();

            // BCrypt.checkpw compara a senha digitada com o hash salvo no JSON.
            // Nunca usamos equals para comparar senha pura.
            boolean senhaCorreta = BCrypt.checkpw(request.password, usuario.getSenhaHash());
            if (!senhaCorreta) {
                sendJson(exchange, 401, Map.of("message", "E-mail ou senha invalidos."));
                return;
            }

            // Credenciais corretas: criamos o token e entregamos ao frontend.
            String token = jwtService.generateToken(usuario);
            sendJson(exchange, 200, Map.of("token", token));
        } catch (Exception e) {
            e.printStackTrace();
            sendJson(exchange, 500, Map.of("message", "Erro interno no login."));
        }
    }

    /**
     * Gerencia o cadastro de usuario.
     * A senha chega pura pela requisicao, mas so o hash vai para o arquivo JSON.
     */
    public void handleRegister(HttpExchange exchange) throws IOException {
        addCorsHeaders(exchange);
        if (handleOptions(exchange)) return;

        if (!"POST".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }

        try {
            RegisterRequest request = mapper.readValue(exchange.getRequestBody(), RegisterRequest.class);

            // Impede dois cadastros com o mesmo e-mail.
            if (repository.findByEmail(request.email).isPresent()) {
                sendJson(exchange, 400, Map.of("message", "E-mail ja cadastrado."));
                return;
            }

            // Gera o hash com custo 12, como pedido no trabalho.
            String senhaHash = BCrypt.hashpw(request.password, BCrypt.gensalt(12));

            // Role simples para o projeto. O professor pediu claim de cargo/perfil no JWT.
            Usuario novoUsuario = new Usuario(request.name, request.email, senhaHash, "USER");

            repository.save(novoUsuario);
            sendJson(exchange, 201, Map.of("message", "Usuario cadastrado com sucesso."));
        } catch (Exception e) {
            e.printStackTrace();
            sendJson(exchange, 500, Map.of("message", "Erro interno no cadastro."));
        }
    }

    /**
     * Exemplo de rota protegida.
     * So responde 200 quando recebe um Bearer Token valido no header Authorization.
     */
    public void handleProtected(HttpExchange exchange) throws IOException {
        addCorsHeaders(exchange);
        if (handleOptions(exchange)) return;

        String authorization = exchange.getRequestHeaders().getFirst("Authorization");
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            sendJson(exchange, 401, Map.of("message", "Token nao enviado."));
            return;
        }

        String token = authorization.substring("Bearer ".length());
        if (!jwtService.validateToken(token)) {
            sendJson(exchange, 401, Map.of("message", "Token invalido ou expirado."));
            return;
        }

        String email = jwtService.extractEmail(token);
        sendJson(exchange, 200, Map.of("message", "Acesso autorizado.", "email", email));
    }

    /**
     * Logout simples para combinar com o frontend.
     * Como JWT nao fica salvo no servidor, basta o frontend apagar o token.
     */
    public void handleLogout(HttpExchange exchange) throws IOException {
        addCorsHeaders(exchange);
        if (handleOptions(exchange)) return;

        sendJson(exchange, 200, Map.of("message", "Logout realizado."));
    }

    private void addCorsHeaders(HttpExchange exchange) {
        // Permite que o HTML aberto no navegador consiga chamar localhost:8080.
        exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type, Authorization");
        exchange.getResponseHeaders().add("Content-Type", "application/json; charset=UTF-8");
    }

    private boolean handleOptions(HttpExchange exchange) throws IOException {
        // O navegador pode enviar OPTIONS antes do POST por causa do CORS.
        if ("OPTIONS".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(204, -1);
            return true;
        }
        return false;
    }

    private void sendJson(HttpExchange exchange, int statusCode, Object body) throws IOException {
        // Converte o objeto Java para JSON e depois para bytes UTF-8.
        byte[] resposta = mapper.writeValueAsString(body).getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(statusCode, resposta.length);
        exchange.getResponseBody().write(resposta);
        exchange.close();
    }

    public static class LoginRequest {
        public String email;
        public String password;
    }

    public static class RegisterRequest {
        public String name;
        public String email;
        public String password;
    }
}
