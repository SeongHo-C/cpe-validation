from django.contrib import admin

from .models import Component, DockerImage, SBOMDocument


admin.site.register(DockerImage)
admin.site.register(SBOMDocument)
admin.site.register(Component)
