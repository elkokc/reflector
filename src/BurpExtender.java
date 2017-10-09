package burp;


import javax.swing.*;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.List;

import static burp.MapConstants.*;


public class BurpExtender implements IBurpExtender, IScannerCheck, ITab
{
    public static final String PLUGIN_NAME = "Reflector";
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private static final String DESCRIPTION_DETAILS = "Reflected parameters in ";
    private static final String XSS_POSIBLE = "XSS (possible)";
    private static final String XSS_VULNERABLE= "XSS (vulnerable)";
    String issueName = XSS_POSIBLE;
    public static final String ALLOWED_CONTENT_TYPE = "Allowed Content-Type";
    public static final String DELETE = "Delete";
    public static final String ADD = "Add";
    private JPanel panel;
    private final String OPTIONS_NAME = "Scanner options";
    private final String AGRESSIVE_MODE = "Agressive mode";
    private final String SCOPE_ONLY = "Scope only";
    private final String CHECK_CONTEXT = "Check context";
    private JButton addButton;
    private JButton deleteButton;
    private JTextField contetTtypeTextField;
    private JTable table;
    private TableModel model;
    private JCheckBox scopeOnly;
    private JCheckBox agressiveMode;
    private JCheckBox checkContext;
    private Settings settings;

    private CheckReflection checkReflection;

    //
    // implement IBurpExtender
    //

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName(PLUGIN_NAME);

        // register ourselves as a custom scanner check
        callbacks.registerScannerCheck(this);

        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {
                settings = new Settings(callbacks);
                panel = new JPanel();
                panel.setLayout(null);

                final JLabel label1 = new JLabel(OPTIONS_NAME);
                label1.setFont(new Font(label1.getFont().getName(), Font.BOLD, 16));
                label1.setBounds(58, 20, 130, 20);
                panel.add(label1);

                model = new BurpTableModel(settings);

                table=new JTable(model);
                TableColumnModel columnModel = table.getColumnModel();
                columnModel.getColumn(0).setPreferredWidth(65);
                columnModel.getColumn(1).setPreferredWidth(330);

                JScrollPane sp = new JScrollPane(table);
                table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
                sp.setBounds(58, 200, 400, 250);
                sp.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
                sp.setPreferredSize(new Dimension(400, 250));

                deleteButton = new JButton(DELETE);
                deleteButton.setBounds(58, 470, 130, 30  );
                panel.add(deleteButton);
                panel.add(sp);

                contetTtypeTextField = new JTextField();
                contetTtypeTextField.setBounds(200, 143, 160, 29);
                panel.add(contetTtypeTextField);
                contetTtypeTextField.setColumns(10);

                JLabel addLabel = new JLabel(ALLOWED_CONTENT_TYPE);
                addLabel.setBounds(58, 150, 140, 16);
                addLabel.setFont(new Font(label1.getFont().getName(), Font.PLAIN ,14));
                panel.add(addLabel);
                addButton = new JButton(ADD);
                addButton.setBounds(370, 143, 84, 30);
                panel.add(addButton);
                BurpExtender.OptionPanel optionPanel1 = placeOption(SCOPE_ONLY);
                JPanel option1 = optionPanel1.getPanel();
                scopeOnly = optionPanel1.getCheckBox();
                scopeOnly.setSelected(settings.getScopeOnly());
                option1.setBounds(58, 43, 130, 20);
                panel.add(option1);
                BurpExtender.OptionPanel optionPanel2 = placeOption(AGRESSIVE_MODE);
                JPanel option2 = optionPanel2.getPanel();
                agressiveMode = optionPanel2.getCheckBox();
                agressiveMode.setSelected(settings.getAgressiveMode());
                option2.setBounds(58, 63, 130, 20);
                panel.add(option2);
                BurpExtender.OptionPanel optionPanel3 = placeOption(CHECK_CONTEXT);
                JPanel option3 = optionPanel3.getPanel();
                checkContext = optionPanel3.getCheckBox();
                checkContext.setSelected(settings.getCheckContext());
                option3.setBounds(58, 83, 130, 20);
                panel.add(option3);


                initListener();


                callbacks.customizeUiComponent(panel);
                callbacks.addSuiteTab(BurpExtender.this);
            }
        });
    }

    //listener  initializations
    private void initListener(){

        //add button
        addButton.addActionListener(new ActionListener(){

            @Override
            public void actionPerformed(ActionEvent e) {
                String type = contetTtypeTextField.getText();
                Object[] rowData = {Boolean.TRUE, type};
                ((BurpTableModel)model).addRow(rowData);
            }
        });

        //delete button
        deleteButton.addActionListener(new ActionListener(){

            @Override
            public void actionPerformed(ActionEvent e) {
                int i = table.getSelectedRow();
                if(i >= 0){
                    ((BurpTableModel)model).removeRow(i);
                }
            }
        });

        //table checkboxes
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int column = table.getSelectedColumn();
                int row = table.getSelectedRow();
                if(column == 0 && row >=0){
                    Boolean value = (Boolean)model.getValueAt(row,column);
                    value = !value;
                    model.setValueAt(value, row, column);
                }
            }
        });

        //checkbox option
        scopeOnly.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent event) {
                settings.setScopeOnly(scopeOnly.isSelected());
            }
        });

        //checkbox option
        agressiveMode.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                settings.setAgressiveMode(agressiveMode.isSelected());
            }
        });

        //checkbox option
        checkContext.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                settings.setCheckContext(checkContext.isSelected());
            }
        });

    }

    private OptionPanel placeOption(String optionName)
    {
        JPanel panelOption = new JPanel();
        BoxLayout boxlayout = new BoxLayout(panelOption, BoxLayout.X_AXIS);
        panelOption.setLayout(boxlayout);
        JCheckBox checkBox1 = new JCheckBox();
        checkBox1.setText("");
        panelOption.add(checkBox1);
        panelOption.add(Box.createRigidArea(new Dimension(5, 5)));
        final JLabel label1 = new JLabel();
        label1.setText(optionName);
        label1.setFont(new Font(label1.getFont().getName(), Font.PLAIN, 14));
        panelOption.add(label1);
        panelOption.setAlignmentX(Component.LEFT_ALIGNMENT);
        return new OptionPanel(panelOption, checkBox1);
    }

    @Override
    public String getTabCaption()
    {
        return PLUGIN_NAME;
    }

    @Override
    public Component getUiComponent()
    {
        return panel;
    }



    final class OptionPanel {
        private final JPanel panel;
        private final JCheckBox checkBox;

        public OptionPanel(JPanel panel, JCheckBox checkbox) {
            this.panel = panel;
            this.checkBox = checkbox;
        }

        public JPanel getPanel() {
            return panel;
        }

        public JCheckBox getCheckBox() {
            return checkBox;
        }
    }

    // helper method to search a response for occurrences of a literal match string
    // and return a list of start/end offsets
    private List<int[]> getMatches(byte[] response, byte[] match)
    {
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

    //
    // implement IScannerCheck
    //

    private String buildIssueForReflection( Map param)
    {
        String reflectedIn = "";
        reflectedIn+="<li>";
        reflectedIn+=param.get(NAME);
        reflectedIn+=" - reflected "+ String.valueOf(((List)param.get(MATCHES)).size())+" times ";
        if (param.containsKey(VULNERABLE))
        {
            reflectedIn += "and allow the next characters: "+ String.valueOf(param.get(VULNERABLE));
            if (settings.getCheckContext() && !String.valueOf(param.get(VULNERABLE)).contains(CONTEXT_VULN_FLAG))
                return reflectedIn+ "</li>" ;
            issueName = XSS_VULNERABLE;
        }
        return reflectedIn+ "</li>" ;
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) throws MalformedURLException {
        if ( this.settings.getScopeOnly() && !callbacks.isInScope(helpers.analyzeRequest(baseRequestResponse).getUrl()) )
            return null;
        // check content type
        String contentType = "";
        for (String header: helpers.analyzeResponse(baseRequestResponse.getResponse()).getHeaders()) {
            if (header.toLowerCase().contains("content-type: ")) {
                contentType = header.toLowerCase().split(": ", 2)[1];
                break;
            }
        }
        if (settings.getEnabledContentTypes() == null)
            return null;
        boolean isContentTypeAllowed = false;
        for (String allowedContentType: settings.getEnabledContentTypes()) {
            if (contentType.contains(allowedContentType)) {
                contentType = allowedContentType;
                isContentTypeAllowed = true;
                break;
            }
        }
        issueName = XSS_POSIBLE;
        // start analyze request
        if ( isContentTypeAllowed )
        {
            //Initialize check reflections
            this.checkReflection = new CheckReflection(settings, helpers, baseRequestResponse, callbacks);
            List<Map> reflections = this.checkReflection.checkResponse();
            if (!reflections.isEmpty())
            {
                // report the issue
                String reflectedInBody = "";
                String reflectedInHeader = "";
                String reflectedInAll = "";
                List<int[]> matches = new ArrayList<>();
                List<Pair> pairs = new ArrayList<>();
                for(Map param: reflections) {

                    if(param.get(REFLECTED_IN).equals(BODY)){
                        reflectedInBody+=buildIssueForReflection(param);
                    }

                    if(param.get(REFLECTED_IN).equals(HEADERS)){
                        reflectedInHeader+=buildIssueForReflection(param);
                    }


                    if(param.get(REFLECTED_IN).equals(BOTH)){
                        reflectedInAll+=buildIssueForReflection(param);
                    }


                    for (Object pair : (ArrayList)param.get(MATCHES)) {
                        pairs.add(new Pair((int[]) pair));
                    }
                }
                String START = ":<br><ul>";
                String END = "</ul>";
                String reflectedSummary = "";
                if(!reflectedInHeader.equals(""))
                    reflectedSummary+=DESCRIPTION_DETAILS + HEADERS+START+reflectedInHeader+END;
                if(!reflectedInBody.equals(""))
                    reflectedSummary+=DESCRIPTION_DETAILS + BODY + START + reflectedInBody+END;
                if(!reflectedInAll.equals(""))
                    reflectedSummary+=DESCRIPTION_DETAILS+BOTH+START+reflectedInAll+END;
                Collections.sort(pairs, new Comparator<Pair>() {
                    @Override
                    public int compare(Pair o1, Pair o2) {
                        if (o1.getStart() == o2.getStart())
                            return 0;
                        return o1.getStart() < o2.getStart() ? -1 : 1;
                    }
                });
                int[] tmpPair = null;
                for (Pair pair : pairs)
                {
                    if (tmpPair == null)
                        tmpPair = pair.getPair();
                    else if (tmpPair[1] > pair.getPair()[0])
                        tmpPair[1] = pair.getPair()[1];
                    else {
                        matches.add(tmpPair);
                        tmpPair = pair.getPair();
                    }
                }
                if (tmpPair != null) {
                    matches.add(tmpPair);
                }
                List<IScanIssue> issues = new ArrayList<>();
                issues.add(new CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        new IHttpRequestResponse[]{callbacks.applyMarkers(baseRequestResponse, null, matches)},
                        issueName,
                        reflectedSummary,
                        getSeverity(issueName)));
                return issues;
            } else return null;
        }
        else return null;
    }

    private String getSeverity(String issueName) {
        return XSS_VULNERABLE.equals(issueName) ? "High" : "Medium";
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint)
    {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    {
        if (existingIssue.getIssueDetail().equals(newIssue.getIssueDetail()))
        {
            return -1;
        } else {
            return 0;
        }
    }
}

//
// class implementing IScanIssue to hold our custom scan issue details
//
class CustomScanIssue implements IScanIssue
{
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;

    public CustomScanIssue(
            IHttpService httpService,
            URL url,
            IHttpRequestResponse[] httpMessages,
            String name,
            String detail,
            String severity)
    {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
    }

    @Override
    public URL getUrl()
    {
        return url;
    }

    @Override
    public String getIssueName()
    {
        return name;
    }

    @Override
    public int getIssueType()
    {
        return 0;
    }

    @Override
    public String getSeverity()
    {
        return severity;
    }

    @Override
    public String getConfidence()
    {
        return "Certain";
    }

    @Override
    public String getIssueBackground()
    {
        return null;
    }

    @Override
    public String getRemediationBackground()
    {
        return null;
    }

    @Override
    public String getIssueDetail()
    {
        return detail;
    }

    @Override
    public String getRemediationDetail()
    {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages()
    {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService()
    {
        return httpService;
    }

}