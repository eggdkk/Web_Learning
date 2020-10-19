$(document).ready(function() {
    var productImageGroups = [];
    $('.img-fluid').each(function() { 
        var productImageSource = $(this).attr('src');
        var productImageTag = $(this).attr('tag');
        var productImageTitle = $(this).attr('title');
        if ( productImageTitle != undefined ){
            productImageTitle = 'title="' + productImageTitle + '" '
        }
        else {
            productImageTitle = ''
        }
        $(this).wrap('<a class="boxedThumb ' + productImageTag + '" ' + productImageTitle + 'href="' + productImageSource + '"></a>');
        productImageGroups.push('.'+productImageTag);
    });
    jQuery.unique( productImageGroups );
    productImageGroups.forEach(productImageGroupsSet);
    function productImageGroupsSet(value) {
        $(value).simpleLightbox();
    }
});