package burp;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.jar.Attributes;
import java.util.regex.Pattern;

import static burp.MapConstants.*;

class ContextAnalyzer
{
    private class Tag {
        private int start;
        private int end;
        private String name;
        private ArrayList<Attribute> attrList;

        Tag(int start, int end, String name, ArrayList<Attribute> attrList) {
            this.start = start;
            this.end = end;
            this.name = name;
            this.attrList = attrList;
        }
    }

    private class Attribute {
        private int start;
        private int end;
        private char delimiter;

        Attribute(int start, int end, char delimiter) {
            this.start = start;
            this.end = end;
            this.delimiter = delimiter;
        }
    }

    private ArrayList<Tag> tagList;
    private int[] startIndexes;
    private String body;

    ContextAnalyzer(String body) {
        this.tagList = new ArrayList<>();
        parseBody(body);
        this.startIndexes = makeStartIndexes();
        this.body = body;
    }

    private int[] makeStartIndexes() {
        int[] tmp = new int[this.tagList.size()];
        for (int i = 0; i < this.tagList.size(); i++) {
            tmp[i] = this.tagList.get(i).start;
        }
        return tmp;
    }

    public String getContext(int start) {
        int place = Arrays.binarySearch( this.startIndexes, start );
        if (place == -1 || place * -1 > this.startIndexes.length) {
            return CONTEXT_OUT_OF_TAG;
        } else {
            place = place * -1 - 1;
            if ( this.tagList.get(place - 1).end < start &&  this.tagList.get(place).start > start) {
                if ( this.tagList.get(place - 1).name.equals("script") ) {
                    return checkScript( place - 1, start );
                }
                return CONTEXT_OUT_OF_TAG;
            }
            return checkContextInTag( this.tagList.get(place - 1).attrList, start );
        }
    }

    private String checkScript(int place, int start) {
        String tmpContext = this.body.substring( this.tagList.get(place).end, start ).replaceAll("\\[\"']", "");
        System.out.println(tmpContext);
        int quote = 0;
        int doubleQuote = 0;
        for (char c: tmpContext.toCharArray()) {
            if ( c == '\'' && doubleQuote == 0)
                if ( quote == 1 )
                    quote = 0;
                else
                    quote = 1;
            else if ( c == '"' && quote == 0 )
                if ( doubleQuote == 1 )
                    doubleQuote = 0;
                else
                    doubleQuote = 1;
        }
        if (quote == 1)
            return CONTEXT_IN_SCRIPT_TAG_STRING_Q;
        if (doubleQuote == 1)
            return CONTEXT_IN_SCRIPT_TAG_STRING_DQ;
        return CONTEXT_IN_SCRIPT_TAG;


    }

    private String checkContextInTag(ArrayList<Attribute> attrList, int start) {
        boolean inAttribute = false;
        char delimiter = '\0';
        for (Attribute attr: attrList) {
            if ( attr.start <= start && attr.end >= start ) {
                delimiter = attr.delimiter;
                break;
            }
        }
        switch (delimiter) {
            case '\'':
                return CONTEXT_IN_ATTRIBUTE_Q;
            case '"':
                return CONTEXT_IN_ATTRIBUTE_DQ;
            default:
                return CONTEXT_IN_TAG;
        }
    }

    private void parseBody(String body) {
        String alphabet = "qwer/tyuiopasdfghjklzxcvbnm";
        String name = "";
        int attr_step = -1;
        char attr_delimiter = '\0';
        int start_tag = -1;
        int start_attr = -1;
        int i = 0;
        String tmp_name = "";
        int body_length = body.length();
        ArrayList<Attribute> tmpAttributes = null;

        while (i < body_length) {
            if (start_tag == -1) {
                if (body.charAt(i) == '<' && (body_length > i + 1) && alphabet.contains(String.valueOf(body.charAt(i+1)))) {
                    start_tag = i;
                    tmpAttributes = new ArrayList<Attribute>();
                }
                i += 1;
            } else if (start_attr == -1) {
                while ((name == "") && (i < body_length)) {
                    if (body.charAt(i) == '>' || body.charAt(i) == ' ') {
                        name = tmp_name;
                        tmp_name = "";
                    } else {
                        tmp_name += body.charAt(i);
                        i += 1;
                    }
                }
                while ((start_attr == -1) && (i < body_length)) {
                    if (body.charAt(i) == '>') {
                        tagList.add(new Tag(start_tag, i, name, tmpAttributes));
                        tmpAttributes = null;
                        name = "";
                        tmp_name = "";
                        start_tag = -1;
                        start_attr = -1;
                        attr_step = -1;
                        attr_delimiter = '\0';
                        i += 1;
                        break;
                    } else if (attr_step == -1) {
                        if (body.charAt(i) != ' ')
                            attr_step = 0;
                    } else if (attr_step == 0) {
                        if (body.charAt(i) == ' ')
                            attr_step = 1;
                        else if (body.charAt(i) == '=')
                            attr_step = 2;
                    } else if (attr_step == 1) {
                        if (body.charAt(i) == '=')
                            attr_step = 2;
                        else if (body.charAt(i) != ' ')
                            attr_step = -1;
                    } else if (attr_step == 2) {
                        if (body.charAt(i) == '"' || body.charAt(i) == '\'') {
                            attr_delimiter = body.charAt(i);
                            start_attr = i;
                        } else if (body.charAt(i) != ' ') {
                            start_attr = i - 1;
                        }
                    }
                    i += 1;
                }
            } else {
                if ((body.charAt(i) == attr_delimiter && body.charAt(i - 1) != '\\' ) || (attr_delimiter == '\0' && " >/".contains(String.valueOf(body.charAt(i))))){
                    tmpAttributes.add(new Attribute(start_attr + 1, i, attr_delimiter));
                    start_attr = -1;
                    attr_step = -1;
                    attr_delimiter = '\0';
                } else {
                    i += 1;
                }
            }
        }
    }
}