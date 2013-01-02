Behaviour.specify("INPUT.mech-auto-complete", 'mechAutocomplete', 1000, function(e) {
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
});
