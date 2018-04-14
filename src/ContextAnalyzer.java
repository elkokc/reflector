package burp;

import static burp.MapConstants.*;

import java.util.ArrayList;
import java.util.Arrays;

class ContextAnalyzer {
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

  private class Reflection {
    private int start;
    private String value;

    Reflection(int start, String value) {
      this.start = start;
      this.value = value;
    }

    public int getStart() {
      return this.start;
    }
  }

  private ArrayList<Tag> tagList;
  private int[] startIndexes;
  private String body;
  private boolean vulnerableFlag;
  private ArrayList<Reflection> reflections;

  ContextAnalyzer(String body, ArrayList<int[]> indexes) {
    this.tagList = new ArrayList<>();
    this.body = prepareBody(body, indexes);
    parseBody(this.body);
    deleteTagsBetweenScript();
    this.startIndexes = makeStartIndexes();
    this.vulnerableFlag = false;
  }

  private int[] makeStartIndexes() {
    int[] tmp = new int[this.tagList.size()];

    for (int i = 0; i < this.tagList.size(); i++) {
      tmp[i] = this.tagList.get(i).start;
    }

    return tmp;
  }

  public String getContext(int start) {
    int place = Arrays.binarySearch(this.startIndexes, start);

    if (place == -1 || place * -1 > this.startIndexes.length || place > -1) {
      return CONTEXT_OUT_OF_TAG;
    } else {
      place = place * -1 - 1;

      if (this.tagList.get(place - 1).end < start
          && this.tagList.get(place).start > start) {
        if (this.tagList.get(place - 1).name.equals("script")) {
          return checkScript(place - 1, start);
        }

        return CONTEXT_OUT_OF_TAG;
      }

      return checkContextInTag(this.tagList.get(place - 1).attrList, start);
    }
  }

  public String getIssuesForAllParameters() {
    String reflectedPayloadValue = "", contextChars = null, context = "",
           symbols = "";

    for (Reflection payload : this.reflections) {
      reflectedPayloadValue = Aggressive.prepareReflectedPayload(payload.value);

      if (reflectedPayloadValue.length() > 0 && payload.getStart() >= 0) {
        context = getContext(payload.getStart());
        contextChars = checksContextSecurity(reflectedPayloadValue, context);

        if (contextChars != null) {
          this.vulnerableFlag = true;
          symbols += String.valueOf(context);
          reflectedPayloadValue = reflectedPayloadValue.replace(contextChars, "");

          if (reflectedPayloadValue.length() > 0) {
            symbols += "\nother chars: ";
          }
        }

        if (reflectedPayloadValue.length() > 0) {
          for (String str : reflectedPayloadValue.split("")) {
            symbols += str + " ";
          }
        }

        symbols = symbols + " || ";
      }
    }

    if (!symbols.equals("")) {
      symbols =
        symbols
        .substring(0, symbols.length() - 4)
        .replaceAll("<", "&lt;")
        .replaceAll("'", "&#39;")
        .replaceAll("\"", "&quot;")
        .replaceAll("\\|\\|", "<b>|</b>")
        .replaceAll("\\n", "<br>");

      if (vulnerableFlag) {
        symbols += CONTEXT_VULN_FLAG;
      }
    }

    return symbols;
  }

  private String checkScript(int place, int start) {
    String tmpContext =
      this.body.substring(this.tagList.get(place).end, start).replaceAll("\\[\"']",
          "");
    int quote = 0;
    int doubleQuote = 0;

    for (char c : tmpContext.toCharArray()) {
      if (c == '\'' && doubleQuote == 0)
        if (quote == 1) {
          quote = 0;
        } else {
          quote = 1;
        } else if (c == '"' && quote == 0)
        if (doubleQuote == 1) {
          doubleQuote = 0;
        } else {
          doubleQuote = 1;
        }
    }

    if (quote == 1) {
      return CONTEXT_IN_SCRIPT_TAG_STRING_Q;
    }

    if (doubleQuote == 1) {
      return CONTEXT_IN_SCRIPT_TAG_STRING_DQ;
    }

    return CONTEXT_IN_SCRIPT_TAG;
  }

  private String checkContextInTag(ArrayList<Attribute> attrList, int start) {
    char delimiter = '\0';

    for (Attribute attr : attrList) {
      if (attr.start <= start && attr.end >= start) {
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

  private void deleteTagsBetweenScript() {
    ArrayList<Tag> tmpTags = new ArrayList<>();
    boolean script = false;

    for (Tag tag : this.tagList) {
      if (tag.name.equals("script") && !script) {
        script = true;
        tmpTags.add(tag);
        continue;
      } else if (tag.name.equals("/script") && script) {
        script = false;
        tmpTags.add(tag);
        continue;
      }

      if (script) {
        continue;
      }

      tmpTags.add(tag);
    }

    this.tagList = tmpTags;
  }

  private String prepareBody(String body, ArrayList<int[]> indexes) {
    String tmpBody = body;
    this.reflections = new ArrayList<>();
    int totalShift = 0;

    for (int[] indexPair : indexes) {
      if (indexPair[0] < 0) {
        continue;
      }

      this.reflections.add(
        new Reflection(
          indexPair[0] - totalShift,
          tmpBody.substring(indexPair[0] - totalShift, indexPair[1] - totalShift)));
      tmpBody =
        tmpBody.substring(0, indexPair[0] - totalShift)
        + tmpBody.substring(indexPair[1] - totalShift);
      totalShift += indexPair[1] - indexPair[0];
    }

    return tmpBody;
  }

  private void parseBody(String body) {
    String alphabet = "qwer/tyuiopasdfghjklzxcvbnm", name = "", tmpName = "";
    int attrStep = -1, startTag = -1, startAttr = -1, i = 0,
        bodyLength = body.length();
    char attrDelimiter = '\0';
    ArrayList<Attribute> tmpAttributes = null;

    while (i < bodyLength) {
      if (startTag == -1) {
        if (body.charAt(i) == '<'
            && (bodyLength > i + 1)
            && alphabet.contains(String.valueOf(body.charAt(i + 1)))) {
          startTag = i;
          tmpAttributes = new ArrayList<Attribute>();
        }

        i += 1;
      } else if (startAttr == -1) {
        while ((name.equals("")) && (i < bodyLength)) {
          if (body.charAt(i) == ' ' || body.charAt(i) == '>') {
            name = tmpName;
            tmpName = "";
          } else {
            tmpName += body.charAt(i);
            i += 1;
          }
        }

        while ((startAttr == -1) && (i < bodyLength)) {
          if (body.charAt(i) == '>') {
            tagList.add(new Tag(startTag, i, name, tmpAttributes));
            tmpAttributes = null;
            name = "";
            tmpName = "";
            startTag = -1;
            startAttr = -1;
            attrStep = -1;
            attrDelimiter = '\0';
            i += 1;
            break;
          } else if (attrStep == -1) {
            if (body.charAt(i) != ' ') {
              attrStep = 0;
            }
          } else if (attrStep == 0) {
            if (body.charAt(i) == ' ') {
              attrStep = 1;
            } else if (body.charAt(i) == '=') {
              attrStep = 2;
            }
          } else if (attrStep == 1) {
            if (body.charAt(i) == '=') {
              attrStep = 2;
            } else if (body.charAt(i) != ' ') {
              attrStep = -1;
            }
          } else if (attrStep == 2) {
            if (body.charAt(i) == '"' || body.charAt(i) == '\'') {
              attrDelimiter = body.charAt(i);
              startAttr = i;
            } else if (body.charAt(i) != ' ') {
              startAttr = i - 1;
            }
          }

          i += 1;
        }
      } else {
        if ((body.charAt(i) == attrDelimiter && body.charAt(i - 1) != '\\')
            || (attrDelimiter == '\0' && " >/".contains(String.valueOf(body.charAt(i))))) {
          tmpAttributes.add(new Attribute(startAttr + 1, i, attrDelimiter));
          startAttr = -1;
          attrStep = -1;
          attrDelimiter = '\0';
        } else {
          i += 1;
        }
      }
    }
  }

  private String checksContextSecurity(String reflectedPayload, String context) {
    String contextChars = null;

    switch (context) {
    case CONTEXT_OUT_OF_TAG: {
      if (reflectedPayload.contains("<")) {
        contextChars = "<";
      }
    }
    break;

    case CONTEXT_IN_ATTRIBUTE_Q: {
      if (reflectedPayload.contains("'")) {
        contextChars = "'";
      }
    }
    break;

    case CONTEXT_IN_ATTRIBUTE_DQ: {
      if (reflectedPayload.contains("\"")) {
        contextChars = "\"";
      }
    }
    break;

    case CONTEXT_IN_TAG: {
      if (reflectedPayload.length() > 0) {
        contextChars = reflectedPayload;
      } else {
        contextChars = "ALL";
      }
    }
    break;

    case CONTEXT_IN_SCRIPT_TAG_STRING_Q: {
      if (reflectedPayload.contains("'")) {
        contextChars = "'";
      }
    }
    break;

    case CONTEXT_IN_SCRIPT_TAG_STRING_DQ: {
      if (reflectedPayload.contains("\"")) {
        contextChars = "\"";
      }
    }
    break;

    case CONTEXT_IN_SCRIPT_TAG: {
      if (reflectedPayload.length() > 0) {
        contextChars = reflectedPayload;
      } else {
        contextChars = "ALL";
      }
    }
    break;
    }

    return contextChars;
  }
}
