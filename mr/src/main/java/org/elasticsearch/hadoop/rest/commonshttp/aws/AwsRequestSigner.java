package org.elasticsearch.hadoop.rest.commonshttp.aws;

import com.amazonaws.auth.*;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HostConfiguration;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.params.HostParams;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.elasticsearch.hadoop.EsHadoopIllegalStateException;
import org.elasticsearch.hadoop.rest.Request;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.time.Instant;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Date;

public class AwsRequestSigner {

    private static final Log log = LogFactory.getLog(AwsRequestSigner.class);

    private static final String ELASTICSEARCH = "es";

    private final AWSCredentialsProviderChain credentialsProvider;
    private final String region;
    private final boolean enabled;
    private final String esEndpoint;

    public AwsRequestSigner(String region, boolean enabled, String esEndpoint) {
        this.region = region;
        this.enabled = enabled;
        String esHost;
        try {
            esHost = new URI(esEndpoint).getHost();
        } catch (Exception e) {
            esHost = esEndpoint;
        }
        this.esEndpoint = esHost;

        this.credentialsProvider = new DefaultAWSCredentialsProviderChain();
    }

    public boolean isEnabled() {
        return enabled;
    }

    private AWSCredentials sanitizeCredentials(AWSCredentials credentials) {
        String accessKeyId = null;
        String secretKey   = null;
        String token = null;
        synchronized (credentials) {
            accessKeyId = credentials.getAWSAccessKeyId();
            secretKey   = credentials.getAWSSecretKey();
            if ( credentials instanceof AWSSessionCredentials ) {
                token = ((AWSSessionCredentials) credentials).getSessionToken();
            }
        }
        if (secretKey != null) secretKey = secretKey.trim();
        if (accessKeyId != null) accessKeyId = accessKeyId.trim();
        if (token != null) token = token.trim();

        if (credentials instanceof AWSSessionCredentials) {
            return new BasicSessionCredentials(accessKeyId, secretKey, token);
        }

        return new BasicAWSCredentials(accessKeyId, secretKey);
    }


    public void sign(HttpMethod http, Request request, HostConfiguration hostConfig) {
        if (!enabled) {
            return;
        }

        try {
            AWSCredentials credentials = sanitizeCredentials(credentialsProvider.getCredentials());

            hostConfig.setHost(esEndpoint);
            Date date = Date.from(Instant.now());

            ArrayList<AbstractMap.SimpleEntry<String, String>> headerList = new ArrayList<AbstractMap.SimpleEntry<String, String>>();
            http.setRequestHeader(new Header("Host", esEndpoint));
            for (Header h : http.getRequestHeaders()) {
                headerList.add(new AbstractMap.SimpleEntry<String, String>(h.getName(), h.getValue()));
            }

            ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
            byte[] payload;
            try {
                request.body().writeTo(byteStream);
                payload = byteStream.toByteArray();
            } catch (Exception e) {
                payload = new byte[]{};
            }

            ArrayList<AbstractMap.SimpleEntry<String, String>> queryList = new ArrayList<AbstractMap.SimpleEntry<String, String>>();
            String path = String.valueOf(request.path());
            if (request.params() != null) {
                queryList = AwsSigner.parseQuery(String.valueOf(request.params()));
            }
            int idx = path.indexOf('?');
            if (idx > -1 && idx != path.length() - 1) {
                queryList.addAll(AwsSigner.parseQuery(path.substring(idx + 1)));
                path = path.substring(0, idx);
            }

            String authHeader = "";
            try {
                authHeader = AwsSigner.getAuthHeader(
                        credentials.getAWSAccessKeyId(),
                        credentials.getAWSSecretKey(),
                        date,
                        region,
                        ELASTICSEARCH,
                        request.method().name(),
                        path,
                        headerList,
                        queryList,
                        payload
                );
            } catch (Exception e) {
                log.error(e.getMessage(), e);
            }
            ArrayList<Header> authHeaders = new ArrayList<Header>();
            authHeaders.add(new Header("Authorization", authHeader));
            authHeaders.add(new Header("X-Amz-Date", AwsSigner.formatDateTime(date)));

            if (credentials instanceof AWSSessionCredentials) {
                authHeaders.add(new Header("X-Amz-Security-Token", ((AWSSessionCredentials) credentials).getSessionToken()));
            }

            HostParams hostParams = new HostParams();
            hostParams.setParameter(HostParams.DEFAULT_HEADERS, authHeaders);
            log.trace("Authorization header: " + authHeader);
            hostConfig.setParams(hostParams);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            throw new EsHadoopIllegalStateException(e);
        }

    }

}
