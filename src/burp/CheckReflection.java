package burp;

import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.Constants.*;

public class CheckReflection {

    public static final int QUOTE_BYTE = 34;
    private final int bodyOffset;

    private IExtensionHelpers helpers;
    private IHttpRequestResponse iHttpRequestResponse;
    private Settings settings;
    IBurpExtenderCallbacks callbacks;

    public CheckReflection(Settings settings, IExtensionHelpers helpers, IHttpRequestResponse iHttpRequestResponse, IBurpExtenderCallbacks callbacks) {
                    this.settings = settings;
                    this.helpers = helpers;
                    this.callbacks = callbacks;
                    this.iHttpRequestResponse = iHttpRequestResponse;
                    this.bodyOffset = helpers.analyzeResponse(iHttpRequestResponse.getResponse()).getBodyOffset();
                }

                    public List<Map> checkResponse() {
                    List<Map> reflectedParameters = new ArrayList<>();
                    List<IParameter> parameters = helpers.analyzeRequest(iHttpRequestResponse).getParameters();
                    byte[] request = iHttpRequestResponse.getRequest();
                    for (IParameter parameter : parameters){
                        byte[] bytesOfParamValue = helpers.urlDecode(parameter.getValue().getBytes());
                        if (bytesOfParamValue.length > 2)
                        {
                            byte b = request[parameter.getValueStart() - 1];
                            if(parameter.getType() == IParameter.PARAM_JSON && b != QUOTE_BYTE){
                                continue;
                            }
                            List<int[]> listOfMatches = getMatches(iHttpRequestResponse.getResponse(), bytesOfParamValue);
                            if (!listOfMatches.isEmpty())
                            {
                    Map parameterDescription = new HashMap();
                    parameterDescription.put(NAME, parameter.getName());
                    parameterDescription.put(VALUE, parameter.getValue());
                    parameterDescription.put(TYPE, parameter.getType());
                    parameterDescription.put(VALUE_START, parameter.getValueStart());
                    parameterDescription.put(VALUE_END, parameter.getValueEnd());
                    parameterDescription.put(MATCHES, listOfMatches);
                    parameterDescription.put(REFLECTED_IN, checkWhereReflectionPlaced(listOfMatches));
                    reflectedParameters.add(parameterDescription);
                }
            }
        }
        if ( settings.getAggressiveMode() && !reflectedParameters.isEmpty() )
        {
            Aggressive scan = new Aggressive(settings, helpers, iHttpRequestResponse, callbacks, reflectedParameters);
            scan.scanReflectedParameters();
        } else if ( settings.getCheckContext() && !reflectedParameters.isEmpty() ) {
            String symbols = "",
                    body = new String(iHttpRequestResponse.getResponse()).substring(this.bodyOffset);
            ArrayList<int[]> payloadIndexes = null;
            //cycle by parameters
            for (Map parameter : reflectedParameters) {
                payloadIndexes = new ArrayList<>();

                for (int[] indexPair: (ArrayList<int[]>) parameter.get(MATCHES)) {
                    int[] tmpIndexes = new int[] { indexPair[0] - this.bodyOffset, indexPair[1] - this.bodyOffset };
                    payloadIndexes.add( tmpIndexes );
                }

                ContextAnalyzer contextAnalyzer = new ContextAnalyzer( body.toLowerCase(), payloadIndexes );
                symbols = contextAnalyzer.getIssuesForAllParameters();
                if ( symbols.length() > 0 ) {
                    parameter.put(VULNERABLE, symbols);
                }
            }
        }
        return reflectedParameters;
    }

    private String checkWhereReflectionPlaced(List<int[]> listOfMatches) {
        String reflectIn = "";
        for(int[] matches : listOfMatches){
            if(matches[0] >= bodyOffset)
                if(reflectIn.equals(HEADERS))
                    return BOTH;
                else
                    reflectIn = BODY;
            else if(reflectIn.equals(BODY))
                    return BOTH;
                else
                    reflectIn = HEADERS;
        }
        return reflectIn;
    }

    private List<int[]> getMatches(byte[] response, byte[] match) {
        List<int[]> matches = new ArrayList<int[]>();

        int start = 0;
        while (start < response.length)
        {
            start = helpers.indexOf(response, match, true, start, response.length);
            if (start == -1)
                break;
            matches.add(new int[] { start, start + match.length });
            start += match.length;
        }

        return matches;
    }
}

class Pair
{
    private int start;
    private int[] pair;
    public Pair(int[] pair)
    {
        this.start = pair[0];
        this.pair = pair;
    }
    public int getStart()
    {
        return start;
    }
    public int[] getPair()
    {
        return pair;
    }
}


class Aggressive
{
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private List<Map> reflectedParameters;
    private IHttpRequestResponse baseRequestResponse;
    private String host;
    private int port;
    private static final String PAYLOAD_GREP = "p@y";
    private static final String PAYLOAD = "<\"'";
    private static final String PAYLOAD_JSON = "<\\\"'";
    private Pattern pattern;
    private Settings settings;

    Aggressive(Settings settings, IExtensionHelpers helpers, IHttpRequestResponse baseRequestResponse, IBurpExtenderCallbacks callbacks, List<Map> reflectedParameters) {
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.reflectedParameters = reflectedParameters;
        this.baseRequestResponse = baseRequestResponse;
        this.host = helpers.analyzeRequest(baseRequestResponse).getUrl().getHost();
        this.port = helpers.analyzeRequest(baseRequestResponse).getUrl().getPort();
        this.pattern = Pattern.compile(PAYLOAD_GREP + "([_%&;\"'<#\\\\0-9a-z]{1,15}?)" + PAYLOAD_GREP);
        this.settings = settings;
    }

    public List<Map> scanReflectedParameters(){
        String testRequest = "",
            symbols = "";
        for (Map param : reflectedParameters)
        {
            if(param.get(REFLECTED_IN) == HEADERS) {
                continue;
            }
            testRequest = prepareRequest(param);
            symbols = checkResponse(testRequest);
            if (!symbols.equals(""))
            {
                param.put(VULNERABLE, symbols);
            }
        }
        return reflectedParameters;
    }

    public static String prepareReflectedPayload(String value) {
        return value.replaceAll("[^<\"'\\\\]", "").replaceAll("(\\\\\"|\\\\')", "").replaceAll("[\\\\]", "");
    }

    private String checkResponse(String testRequest) {
        String  reflectedPayloadValue = "",
                symbols = "";
        int bodyOffset;
        try {
            String response = new Client(callbacks).run(testRequest, host, this.port);
            bodyOffset = response.indexOf("\n\n") + 2;

            Matcher matcher = this.pattern.matcher(response);
            ArrayList<int[]> payloadIndexes = new ArrayList<>();
            while (matcher.find()) {
                payloadIndexes.add( new int[] { matcher.start() - bodyOffset, matcher.end() - bodyOffset } );
            }
            matcher = null;

            if ( settings.getCheckContext() && bodyOffset != 1) {
                ContextAnalyzer contextAnalyzer = new ContextAnalyzer(response.substring(bodyOffset).toLowerCase(), payloadIndexes);
                symbols = contextAnalyzer.getIssuesForAllParameters();
            } else if(bodyOffset != 1) {
                for ( int[] indexPair: payloadIndexes ) {
                    reflectedPayloadValue = Aggressive.prepareReflectedPayload(response.substring(indexPair[0] + bodyOffset, indexPair[1] + bodyOffset));
                    if (reflectedPayloadValue.length() > 0) {
                        for (String str : reflectedPayloadValue.split("")) {
                            symbols += str + " ";
                        }
                    }
                    symbols = symbols + " || ";
                }

                if (!symbols.equals("")) {
                    symbols = symbols.substring(0, symbols.length() - 4).replaceAll("<", "&lt;").replaceAll("'", "&#39;").replaceAll("\"", "&quot;").replaceAll("\\|\\|", "<b>|</b>");
                }
            }
        } catch (IOException e) {
            callbacks.printError(e.getMessage());
            return "";
        } catch (KeyManagementException e) {
            callbacks.printError(e.getMessage());
        } catch (CertificateException e) {
            callbacks.printError(e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            callbacks.printError(e.getMessage());
        } catch (KeyStoreException e) {
            callbacks.printError(e.getMessage());
        }
        return symbols;
    }

    private String prepareRequest(Map parameter) {
        String payload = PAYLOAD;
        if(parameter.get(TYPE).equals(IParameter.PARAM_JSON)){
            payload = PAYLOAD_JSON;
        }

        String tmpRequest = helpers.bytesToString(baseRequestResponse.getRequest()).substring(0, (int)parameter.get("ValueStart")) + PAYLOAD_GREP
                + payload + PAYLOAD_GREP + helpers.bytesToString(baseRequestResponse.getRequest()).substring((int)parameter.get("ValueEnd"));
        String contentLength = "";
        for (String header : helpers.analyzeRequest(baseRequestResponse).getHeaders())
        {
            if(header.toLowerCase().contains("content-length")) {
                contentLength = header;
                break;
            }
        }
        if (contentLength.equals("") || (int)parameter.get(VALUE_START) < helpers.analyzeRequest(baseRequestResponse).getBodyOffset()) {
            return  tmpRequest;
        }
        int paramLength = (int)parameter.get(VALUE_END) - (int)parameter.get(VALUE_START);
        int lengthDiff = (PAYLOAD_GREP + payload + PAYLOAD_GREP).length() - paramLength;
        String contentLengthString = contentLength.split(": ")[1].trim();
        int contentLengthInt = Integer.parseInt(contentLengthString) + lengthDiff;
        int contentLengthIntOffsetStart = tmpRequest.toLowerCase().indexOf("content-length");
        tmpRequest = tmpRequest.substring(0, contentLengthIntOffsetStart + 16) + String.valueOf(contentLengthInt) +
                tmpRequest.substring(contentLengthIntOffsetStart + 16 + contentLengthString.length());
        return tmpRequest;
    }
}