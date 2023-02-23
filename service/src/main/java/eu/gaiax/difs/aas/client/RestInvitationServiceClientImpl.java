package eu.gaiax.difs.aas.client;

import java.net.HttpURLConnection;
import java.net.URL;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class RestInvitationServiceClientImpl implements InvitationServiceClient {

    @Override
    public String getMobileInvitationUrl(String uri) {
    	log.debug("getMobileInvitationUrl.enter; got uri: {}", uri);
        try {
	        URL url = new URL(uri);
	        HttpURLConnection con = (HttpURLConnection) url.openConnection();
	        con.setRequestMethod("GET");
	        con.setInstanceFollowRedirects(false);
	    
	        int status = con.getResponseCode();
	
	        if (status == HttpURLConnection.HTTP_MOVED_TEMP
	            || status == HttpURLConnection.HTTP_MOVED_PERM) {
	                String location = con.getHeaderField("Location");
	                URL newUrl = new URL(location);
	                // TODO: add the constant to config
	                return "gxfspcm://aries_connection_invitation?" + newUrl.getQuery();
	            }          
        } catch (Exception ex) {
        	log.error("getMobileInvitationUrl.error", ex);
        }
        return null;
    }  
}
