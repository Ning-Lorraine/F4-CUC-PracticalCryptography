$(document).ready(function(){
    /*加一减一按钮*/
    $("#max").click(function(){
    var oldValue=parseInt($('#num').val());//取出现在的值，并使用parseInt转为int类型数据
    oldValue++;//自加1
    $('#num').val(oldValue);//将增加后的值付给原控件
    });
    $("#min").click(function(){
    var oldValue=parseInt($('#num').val());//取出现在的值，并使用parseInt转为int类型数据
        if(oldValue==0){
            return;
        }else{
            oldValue--;//自加1
            $('#num').val(oldValue);//将增加后的值付给原控件
        }
    
    });
});
