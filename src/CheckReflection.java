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
import java.util.regex.*;
import static burp.MapConstants.*;

public class CheckReflection {

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
        for (IParameter parameter : parameters){
            byte[] bytesOfParamValue = helpers.urlDecode(parameter.getValue().getBytes());
            if (bytesOfParamValue.length > 2)
            {
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
        if (settings.getAgressiveMode() && !reflectedParameters.isEmpty())
        {
            List<Map> params = new ArrayList<>();
            Aggressive scan = new Aggressive(settings, helpers, iHttpRequestResponse, callbacks, reflectedParameters);
            scan.scanReflectedParameters();
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
class MapConstants
{
    public static final String NAME = "Name";
    public static final String VALUE = "Value";
    public static final String TYPE = "Type";
    public static final String VALUE_START = "ValueStart";
    public static final String VALUE_END = "ValueEnd";
    public static final String MATCHES = "Matches";
    public static final String REFLECTED_IN = "ReflectedIn";
    public static final String VULNERABLE = "Vulnerable";
    public static final String CONTEXT_CHAR = "Context char: ";
    public static final String SCOPE_ONLY = "Scope only";
    public static final String CHECK_CONTEXT = "Check context";
    public static final String AGRESSIVE_MODE = "Agressive mode";
    public static final String HEADERS = "HEADERS";
    public static final String BODY = "BODY";
    public static final String BOTH = "ALL";
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
    private Pattern pattern;
    private Settings settings;

    Aggressive(Settings settings, IExtensionHelpers helpers, IHttpRequestResponse baseRequestResponse, IBurpExtenderCallbacks callbacks, List<Map> reflectedParameters) {
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.reflectedParameters = reflectedParameters;
        this.baseRequestResponse = baseRequestResponse;
        this.host = helpers.analyzeRequest(baseRequestResponse).getUrl().getHost();
        this.port = helpers.analyzeRequest(baseRequestResponse).getUrl().getPort();
        this.pattern = Pattern.compile(PAYLOAD_GREP + "(.{1,15}?)" + PAYLOAD_GREP);
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
            symbols = checkRespone(testRequest);
            if (!symbols.equals(""))
            {
                param.put(VULNERABLE, symbols);
            }
        }
        return reflectedParameters;
    }

    private String checkRespone(String testRequest) {
        String tmp = "",
                symbols = "",
                tmpContext = "";
        try {
            String response = new Client(callbacks).run(testRequest, host, this.port);
            Matcher matcher = this.pattern.matcher(response);
            while (matcher.find())
            {
                tmp = matcher.group(1).replaceAll("[^<\"']", "");
                if (tmp.length() > 0)
                {
                    if (settings.getCheckContext())
                    {
                        String reflectedPayload = PAYLOAD_GREP + matcher.group(1) + PAYLOAD_GREP;
                        Pattern contextBracketPattern = Pattern.compile(">[^<]*" + Pattern.quote(reflectedPayload) + "[^>]*<");
                        Pattern contextScriptOpenPattern = Pattern.compile("<[^<]*script[^<]*>[^<]*" + Pattern.quote(reflectedPayload));
                        tmpContext = getContext(response, matcher);

                        String contextChar = null;

                        Matcher matcherScript = contextScriptOpenPattern.matcher(tmpContext);
                        if ( matcherScript.find() )
                        {
                            contextChar = checkQuotes(tmpContext, reflectedPayload);
                        } else {
                            Matcher matcherBracket = contextBracketPattern.matcher(tmpContext);
                            if ( matcherBracket.find() ) {
                                if ( tmp.contains("<") )
                                    contextChar = "<";
                            } else {
                                contextChar = checkQuotes(tmpContext, reflectedPayload);
                            }
                        }

                        if ( contextChar != null ) {
                            symbols += CONTEXT_CHAR + contextChar + ", other chars: ";
                            tmp = tmp.replace(contextChar, "");
                        }
                    }

                    if (tmp.length() > 0) {
                        for (String str : tmp.split("")) {
                            symbols += str + " ";
                        }
                    }
                    symbols = symbols + " || ";
                }
            }

            if (!symbols.equals(""))
                symbols = symbols.substring(0, symbols.length() - 4).replaceAll("<", "&lt;").replaceAll("'", "&#39;").replaceAll("\"", "&quot;").replaceAll("\\|\\|", "<b>|</b>");
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

    private String checkQuotes(String tmpContext, String reflectedPayload) {
        String qoutesContext = tmpContext.substring(tmpContext.indexOf(reflectedPayload) + reflectedPayload.length());
        int quoteIndex = reflectedPayload.contains("'") ? qoutesContext.indexOf("'"): -1;
        int doubleQuoteIndex = reflectedPayload.contains("\"") ? qoutesContext.indexOf("\""): -1;
        if ( quoteIndex != -1 && ( quoteIndex < doubleQuoteIndex || doubleQuoteIndex == -1) )
            return "'";
        if ( doubleQuoteIndex != -1 && ( doubleQuoteIndex < quoteIndex || quoteIndex == -1) )
            return "\"";
        return null;
    }

    private String prepareRequest(Map parameter) {
        String tmpRequest = helpers.bytesToString(baseRequestResponse.getRequest()).substring(0, (int)parameter.get("ValueStart")) + PAYLOAD_GREP
                + PAYLOAD + PAYLOAD_GREP + helpers.bytesToString(baseRequestResponse.getRequest()).substring((int)parameter.get("ValueEnd"));
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
        int lengthDiff = (PAYLOAD_GREP + PAYLOAD + PAYLOAD_GREP).length() - paramLength;
        String contentLengthString = contentLength.split(": ")[1].trim();
        int contentLengthInt = Integer.parseInt(contentLengthString) + lengthDiff;
        int contentLengthIntOffsetStart = tmpRequest.toLowerCase().indexOf("content-length");
        tmpRequest = tmpRequest.substring(0, contentLengthIntOffsetStart + 16) + String.valueOf(contentLengthInt) +
                tmpRequest.substring(contentLengthIntOffsetStart + 16 + contentLengthString.length());
        return tmpRequest;
    }

    private String getContext(String response, Matcher matcher) {
        int beginIndex = response.substring(0, matcher.start()).lastIndexOf(PAYLOAD_GREP);
        int endIndex = response.substring(matcher.end()).indexOf(PAYLOAD_GREP);
        return response.substring(beginIndex==-1 ? 0 : beginIndex + PAYLOAD_GREP.length(),
                endIndex==-1 ? response.length()-1: endIndex + matcher.end());
    }
}