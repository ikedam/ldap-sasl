/*
 * The MIT License
 * 
 * Copyright (c) 2012-2013 IKEDA Yasuyuki
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

Behaviour.register({"INPUT.mech-auto-complete": function(e) {
    // Retrieve AutoComplete object for this element.
    var ac = null;
    var listeners = YAHOO.util.Event.getListeners(e);
    if(listeners == null){
        return;
    }
    for(var i = 0; i < listeners.length; ++i){
        var listener = listeners[i];
        if(listener.obj && listener.obj instanceof YAHOO.widget.AutoComplete){
            ac = listener.obj;
            break;
        }
    }
    
    
    if(ac == null){
        // failed to retrieve AutoComplete object...
        return;
    }
    
    // set minQueryLength to 0
    // This indicates to open candidates whenever the field is selected.
    ac.minQueryLength = 0
    
    // send all the value to autocomplete handler, not only inputting word.
    ac.generateRequest = function(query) {
        var allValue = this.getInputEl().value;
        var extraction = this._extractQuery(allValue);
        return "?value=" + query + "&previous=" + encodeURIComponent(extraction.previous);
    };
}});
