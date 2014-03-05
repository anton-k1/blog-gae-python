function confirmDelete(post_id)
{
	if (confirm('Are you sure you want to delete post?')) {
		window.location.href = '/_delete/' + post_id;
	} else {
		return false;
	}
}

function validatePostEditForm()
{
	var title = $('#post-title').val();
	var content = $('#post-content').val();
	if (title=='' || content=='')
	{
		alert('Title and content should not be empty');
		return false;
	}
	else
		return true;
}

function validateNewCommentForm()
{
	var title = $('#new-comment-name').val();
	var content = $('#new-comment-text').val();
	if (title=='' || content=='')
	{
		alert('Name and text should not be empty');
		return false;
	}
	else
		return true;	
}

function confirmDeleteComment(comment_id)
{
	if (confirm('Are you sure you want to delete comment?')) {
		window.location.href = '/_delete_comment/' + comment_id;
	} else {
		return false;
	}
}

function validateEmail(email) {
	var email_re = /^[\S]+@[\S]+\.[\S]+$/;
	return email_re.test(email);
}

function validateSubForm()
{
	var sub_name = $('#sub_name').val();
	var sub_email = $('#sub_email').val();
	if (sub_name=='') {
		alert('Name should not be empty');
		return false;
	}
	if (!validateEmail(sub_email)) {
		alert('Email is incorrect');
		return false;
	}

	return true;
}