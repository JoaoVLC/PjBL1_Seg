package com.pucpr.repository;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pucpr.model.Usuario;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class UsuarioRepository {
    private final String FILE_PATH = "usuarios.json";
    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * Busca um usuario pelo e-mail dentro do arquivo JSON.
     */
    public Optional<Usuario> findByEmail(String email) {
        // Se o e-mail vier nulo, ja retornamos vazio para evitar NullPointerException.
        if (email == null) {
            return Optional.empty();
        }

        // Lemos todos os usuarios do JSON e procuramos o primeiro e-mail igual.
        // equalsIgnoreCase faz "ALUNO@email.com" e "aluno@email.com" serem tratados como o mesmo e-mail.
        return findAll().stream()
                .filter(usuario -> usuario.getEmail() != null)
                .filter(usuario -> usuario.getEmail().equalsIgnoreCase(email))
                .findFirst();
    }

    /**
     * Retorna todos os usuarios cadastrados no arquivo JSON.
     */
    public List<Usuario> findAll() {
        File arquivo = new File(FILE_PATH);

        // Se ainda nao existe arquivo, ou se ele esta vazio, significa que ninguem foi cadastrado.
        if (!arquivo.exists() || arquivo.length() == 0) {
            return new ArrayList<>();
        }

        try {
            // O TypeReference informa ao Jackson que queremos uma lista de Usuario.
            return mapper.readValue(arquivo, new TypeReference<List<Usuario>>() {});
        } catch (IOException e) {
            // Transformamos em RuntimeException para avisar que houve erro ao ler o arquivo.
            throw new RuntimeException("Erro ao ler o arquivo de usuarios.", e);
        }
    }

    /**
     * Salva um novo usuario no arquivo JSON.
     */
    public void save(Usuario usuario) throws IOException {
        List<Usuario> usuarios = findAll();

        // Regra de unicidade: nao deixa cadastrar dois usuarios com o mesmo e-mail.
        boolean emailJaExiste = usuarios.stream()
                .anyMatch(usuarioSalvo -> usuarioSalvo.getEmail() != null
                        && usuarioSalvo.getEmail().equalsIgnoreCase(usuario.getEmail()));

        if (emailJaExiste) {
            throw new IllegalArgumentException("E-mail ja cadastrado.");
        }

        usuarios.add(usuario);

        // writerWithDefaultPrettyPrinter deixa o JSON formatado e facil de ler.
        mapper.writerWithDefaultPrettyPrinter().writeValue(new File(FILE_PATH), usuarios);
    }
}
