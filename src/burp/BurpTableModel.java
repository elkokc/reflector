package burp;

import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;


public class BurpTableModel extends AbstractTableModel {

    private ArrayList<Object[]> rowData;

    String columnNames[] = { "Enabled",  "Content-type" };

    BurpTableModel(final Settings settings) {

        rowData = settings.getContentTypes();
        addTableModelListener(new TableModelListener() {

            public void tableChanged(TableModelEvent e) {
                settings.saveContentTypes();
            }
        });
    }

    public void removeRow(int row) {
        rowData.remove(row);
        fireTableRowsDeleted(row, row);
        fireTableDataChanged();
    }

    public void addRow(Object[] row) {
        rowData.add(row);
        fireTableRowsInserted(getRowCount() - 1, getRowCount() - 1);
    }

    public int getColumnCount() {
        return columnNames.length;
    }


    public String getColumnName(int column) {
        return columnNames[column];
    }

    public int getRowCount() {
        return rowData.size();
    }

    public Object getValueAt(int row, int column) {
        return rowData.get(row)[column];
    }

    public Class getColumnClass(int column) {
        return (getValueAt(0, column).getClass());
    }

    public void setValueAt(Object value, int row, int column) {
        Object[] objects = rowData.get(row);
        objects[column] = value;
        rowData.set(row,objects);
        fireTableDataChanged();
    }

    public boolean isCellEditable(int row, int column) {
        return (column != 0);
    }
}
