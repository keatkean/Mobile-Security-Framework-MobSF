from django import forms


class UploadFileForm(forms.Form):
    file = forms.FileField()


class FormUtil(object):

    def __init__(self, form):
        self.form = form

    @staticmethod
    def errors_message(form):
        """Form Errors.

        :param form forms.Form
        form.errors.get_json_data() django 2.0 or higher

        :return
        example
        {
        "error": {
            "file": "This field is required.",
            "test": "This field is required."
            }
        }
        """
        data = form.errors.get_json_data()
        for k, v in data.items():
            data[k] = ' '.join([value_detail['message'] for value_detail in v])
        return data

    @staticmethod
    def errors(form):
        return form.errors.get_json_data()
    
class NameForm(forms.Form):
    type_CHOICES = {'static': 'Static Analysis', 'dynamic': 'Dynamic Analysis'}
    type = forms.ChoiceField(label='Analysis Type', choices=type_CHOICES)
    input_path = forms.CharField(label="File or folder path", max_length=10000)
    activities_CHOICES = {0: "Don't run android activites", 1: "Run android activities"}
    androidactivities = forms.ChoiceField(label='Android Activities', choices=activities_CHOICES)
    useractivities_CHOICES = {0: "Don't run user activites", 1: "Run user activities"}
    useractivities = forms.ChoiceField(label='User Activities', choices=useractivities_CHOICES)
