package org.wso2.choreo.connect.enforcer.interceptor.opa;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.wso2.choreo.connect.enforcer.commons.model.RequestContext;
import org.wso2.choreo.connect.enforcer.constants.APIConstants;
import org.wso2.choreo.connect.enforcer.constants.APISecurityConstants;
import org.wso2.choreo.connect.enforcer.util.FilterUtils;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import java.util.ServiceLoader;

public class OPAClient {
    private static final Logger log = LogManager.getLogger(OPAClient.class);
    private static final OPAClient opaClient = new OPAClient();
    private static final String DEFAULT_REQUEST_GENERATOR_CLASS = "org.wso2.choreo.connect.enforcer.commons.model.RequestContext.OPADefaultRequestGenerator";

    private final Map<String, OPARequestGenerator> requestGeneratorMap = new HashMap<>();

    private OPAClient(){
        loadRequestGenerators();
    }

    public static OPAClient getInstance() {
        return opaClient;
    }

    public boolean validateRequest(RequestContext requestContext, Map<String, String> policyAttrib) throws OPASecurityException {
        String requestGeneratorClassName = policyAttrib.get("requestGenerator");
        OPARequestGenerator requestGenerator = requestGeneratorMap.get(requestGeneratorClassName);
        if (requestGenerator == null) {
            log.error("OPA Request Generator Implementation is not found in the classPath under the provided name: {}",
                    requestGeneratorClassName);
            // TODO: (renuka) check error code?
            throw new OPASecurityException(APIConstants.StatusCodes.INTERNAL_SERVER_ERROR.getCode(),
                    APISecurityConstants.API_AUTH_GENERAL_ERROR,
                    APISecurityConstants.API_AUTH_GENERAL_ERROR_MESSAGE);
        }

        String serverUrl = policyAttrib.get("serverUrl");
        String token = policyAttrib.get("accessToken");
        String policyName = policyAttrib.get("policy");
        String ruleName = policyAttrib.get("rule");
        // TODO: (renuka) handle additionalProperties, check with APIM

        String requestBody = requestGenerator.generateRequest(policyName, ruleName, null, requestContext);
        String evaluatingPolicyUrl = serverUrl + "/" + policyName + "/" + ruleName;
        String opaResponse = callOPAServer(evaluatingPolicyUrl, requestBody, token);
        return requestGenerator.validateResponse(policyName, ruleName, opaResponse, requestContext);
    }

    private void loadRequestGenerators() {
        ServiceLoader<OPARequestGenerator> loader = ServiceLoader.load(OPARequestGenerator.class);
        for (OPARequestGenerator generator: loader) {
            requestGeneratorMap.put(generator.getClass().getName(), generator);
        }
        requestGeneratorMap.put("", requestGeneratorMap.get(DEFAULT_REQUEST_GENERATOR_CLASS));
    }

    private static String callOPAServer(String serverEp, String payload, String token) throws OPASecurityException {
        try {
            URL url = new URL(serverEp);
            try (CloseableHttpClient httpClient = (CloseableHttpClient) FilterUtils.getHttpClient(url.getProtocol())) {
                HttpPost httpPost = new HttpPost(serverEp);
                HttpEntity reqEntity = new ByteArrayEntity(payload.getBytes(Charset.defaultCharset()));
                httpPost.setEntity(reqEntity);
                httpPost.setHeader(APIConstants.CONTENT_TYPE_HEADER, APIConstants.APPLICATION_JSON);
                if (StringUtils.isNotEmpty(token)) {
                    httpPost.setHeader(APIConstants.AUTHORIZATION_HEADER_DEFAULT, token);
                }
                try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
                    if (response.getStatusLine().getStatusCode() == 200) {
                        HttpEntity entity = response.getEntity();
                        try (InputStream content = entity.getContent()) {
                            return IOUtils.toString(content, Charset.defaultCharset());
                        }
                    } else {
                        return null;
                    }
                }
            }
        } catch (IOException e) {
            log.error("Error calling the OPA server with server endpoint: {}", serverEp);
            throw new OPASecurityException(APIConstants.StatusCodes.INTERNAL_SERVER_ERROR.getCode(),
                    APISecurityConstants.API_AUTH_GENERAL_ERROR,
                    APIConstants.SERVER_ERROR, e);
        }
    }
}
