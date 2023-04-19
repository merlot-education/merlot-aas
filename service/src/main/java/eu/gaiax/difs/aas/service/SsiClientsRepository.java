package eu.gaiax.difs.aas.service;

import java.sql.SQLException;
import java.util.List;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import lombok.extern.slf4j.Slf4j;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;

@Slf4j
public class SsiClientsRepository extends JdbcRegisteredClientRepository {
	
	private static final String SELECT_ALL = "select " +
			"id, client_id, client_id_issued_at, client_secret, client_secret_expires_at, client_name, client_authentication_methods, " +
			"authorization_grant_types, redirect_uris, scopes, client_settings, token_settings " +
			"from oauth2_registered_client";

	public SsiClientsRepository(JdbcTemplate jdbcTemplate) {
		super(jdbcTemplate);
		try {
			log.info("<init>; DB URL: {}, User: {}", jdbcTemplate.getDataSource().getConnection().getMetaData().getURL(),
					jdbcTemplate.getDataSource().getConnection().getMetaData().getUserName());
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}
	
	public List<RegisteredClient> getAllClients() {
		List<RegisteredClient> clients = this.getJdbcOperations().query(SELECT_ALL, this.getRegisteredClientRowMapper());
		return clients;
	}

}
