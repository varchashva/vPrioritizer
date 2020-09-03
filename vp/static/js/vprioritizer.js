$(document).ready(function () {
    $(".selectAll").on( "click", function(e) {
        var table = $('#asset_table').DataTable();
        if ($(this).is( ":checked" )) {
            table.rows(  {"search" : "applied"}  ).select();
        } else {
            table.rows( {"search" : "applied"}  ).deselect();
        }
    });

    $(".informational_selected").on( "click", function(e) {
        if ($(this).is( ":checked" )) {
            var table = $('#vuln_table').DataTable();
            table
               .column(2)
               .search("")
               .draw();
        }
        else {
            var table = $('#vuln_table').DataTable();
            table
               .column(2)
               .search("^(?!Informational).*$",true)
               .draw();
        }
    });


    $(".select_asset_accessibility").on( "click", function(e) {
        if ($(this).is( ":checked" )) {
            if ($("#asset_accessibility_filter").val() == "" ) {
                filter = [];
                filter.push(this.value);
                $("#asset_accessibility_filter").val(JSON.stringify(filter));
            }
            else if (! $("#asset_accessibility_filter").val().includes(this.value) ) {
                var filter = JSON.parse($("#asset_accessibility_filter").val());
                filter.push(this.value);
                $("#asset_accessibility_filter").val(JSON.stringify(filter));
            }
            var filter_string_array = JSON.parse($("#asset_accessibility_filter").val());
            var filter_string = "";
            for (var i = 0; i < filter_string_array.length; i++) {

                filter_string = filter_string.concat(filter_string_array[i]).concat("|");
            }
            filter_string = filter_string.substring(0,filter_string.length-1);
            var table = $('#asset_table').DataTable();
            table
               .column(4)
               .search(filter_string,true)
               .draw();
        }
        else {
            var filter_string_array = JSON.parse($("#asset_accessibility_filter").val());
            var filter_string = "";
            var index = filter_string_array.indexOf(this.value);
            if (index > -1) {
                filter_string_array.splice(index, 1);
            }
            $("#asset_accessibility_filter").val(JSON.stringify(filter_string_array));
            var filter_string_array = JSON.parse($("#asset_accessibility_filter").val());
            var filter_string = "";
            for (var i = 0; i < filter_string_array.length; i++) {
                filter_string = filter_string.concat(filter_string_array[i]).concat("|");
            }
            filter_string = filter_string.substring(0,filter_string.length-1);
            var table = $('#asset_table').DataTable();
            table
               .column(4)
               .search(filter_string,true)
               .draw();
        }
    });

    $(".select_asset_criticality").on( "click", function(e) {
        if ($(this).is( ":checked" )) {
            if ($("#asset_criticality_filter").val() == "" ) {
                filter = [];
                filter.push(this.value);
                $("#asset_criticality_filter").val(JSON.stringify(filter));
            }
            else if (! $("#asset_criticality_filter").val().includes(this.value) ) {
                var filter = JSON.parse($("#asset_criticality_filter").val());
                filter.push(this.value);
                $("#asset_criticality_filter").val(JSON.stringify(filter));
            }
            var filter_string_array = JSON.parse($("#asset_criticality_filter").val());
            var filter_string = "";
            for (var i = 0; i < filter_string_array.length; i++) {

                filter_string = filter_string.concat(filter_string_array[i]).concat("|");
            }
            filter_string = filter_string.substring(0,filter_string.length-1);
            var table = $('#asset_table').DataTable();
            table
               .column(3)
               .search(filter_string,true)
               .draw();
        }
        else {
            var filter_string_array = JSON.parse($("#asset_criticality_filter").val());
            var filter_string = "";
            var index = filter_string_array.indexOf(this.value);
            if (index > -1) {
                filter_string_array.splice(index, 1);
            }
            $("#asset_criticality_filter").val(JSON.stringify(filter_string_array));
            var filter_string_array = JSON.parse($("#asset_criticality_filter").val());
            var filter_string = "";
            for (var i = 0; i < filter_string_array.length; i++) {
                filter_string = filter_string.concat(filter_string_array[i]).concat("|");
            }
            filter_string = filter_string.substring(0,filter_string.length-1);
            var table = $('#asset_table').DataTable();
            table
               .column(3)
               .search(filter_string,true)
               .draw();
        }
    });
});
