package eu.gaiax.difs.aas.service;

import java.util.List;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;

public class SsiClientsRepository extends JdbcRegisteredClientRepository {
	
	private static final String SELECT_ALL = "select " +
			"id, client_id, client_id_issued_at, client_secret, client_secret_expires_at, client_name, client_authentication_methods, " +
			"authorization_grant_types, redirect_uris, scopes, client_settings, token_settings " +
			"from oauth2_registered_client";

	public SsiClientsRepository(JdbcOperations jdbcOperations) {
		super(jdbcOperations);
	}
	
	public List<RegisteredClient> getAllClients() {
		List<RegisteredClient> clients = this.getJdbcOperations().query(SELECT_ALL, this.getRegisteredClientRowMapper());
		return clients;
	}

}
