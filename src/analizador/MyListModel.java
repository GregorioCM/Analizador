/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package analizador;

import java.util.Vector;
import javax.swing.DefaultListModel;

/**
 *
 * @author Gregorio
 */
public class MyListModel extends DefaultListModel{
    private Vector<String> data;
    
    public MyListModel(){ data = new Vector<String>(1); }
    public MyListModel(Object[] _data)
    { 
        data = new Vector<String>(_data.length);
        for(int i=0; i< _data.length; ++i)
        {
            data.add((String) _data[i]);
        }
    }
    
    public void insertElement(String _element) { data.add(_element); }
    public String getElement(int _index) { return data.get(_index); }
}
