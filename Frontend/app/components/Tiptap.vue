<template>
    <div class="flex flex-col">
        <div class="flex w-full flex-row items-center justify-between">
            <p class=" block text-sm font-medium text-current">
                {{ props.title }}
            </p>
            <div v-if="editor">
                <button :disabled="!editor.can().chain().focus().toggleBold().run()"
                    :class="{ 'is-active': editor.isActive('bold') }" @click="editor.chain().focus().toggleBold().run()">
                    <IconBold />
                </button>
                <button :disabled="!editor.can().chain().focus().toggleItalic().run()"
                    :class="{ 'is-active': editor.isActive('italic') }"
                    @click="editor.chain().focus().toggleItalic().run()">
                    <IconItalic />
                </button>

                <button :disabled="!editor.can().chain().focus().toggleCode().run()"
                    :class="{ 'is-active': editor.isActive('code') }" @click="editor.chain().focus().toggleCode().run()">
                    <IconCode />
                </button>

                <button :class="{ 'is-active': editor.isActive('paragraph') }"
                    @click="editor.chain().focus().setParagraph().run()">
                    <IconParagraph />
                </button>

            </div>
        </div>
        <div class="group">
            <div
                class="group-focus-within:border-primary-400 form-input t group relative block w-full rounded-md border-[1.5px] border-gray-300 bg-white px-2.5 py-1.5 text-sm text-gray-900 shadow-sm placeholder:text-gray-400 disabled:cursor-not-allowed disabled:opacity-75 group-focus-within:border-[3px] group-focus-within:outline-none  dark:border-gray-700 dark:bg-gray-900 dark:text-white dark:placeholder:text-gray-500">
                <div class="form-control tiptap-editor ">
                    <TiptapEditorContent :editor="editor" class="" />
                </div>
            </div>
        </div>
    </div>
</template>

<script setup>
const props = defineProps({
    title: {
        type: String,
        required: true,
        default: 'Title',
    },
    content: {
        type: String,
        default: '',
        required: true
    }
})

const emit = defineEmits(['update:content'])

const editor = useEditor({
    content: props.content || '',
    extensions: [TiptapStarterKit],
    injectCSS: true,
    onUpdate: () => { emit('update:content', editor.value?.getHTML()) }
})

onBeforeUnmount(() => {
    unref(editor).destroy()
})
</script>

<style>
.tiptap-editor {
    border-top-left-radius: 0;
    border-top-right-radius: 0;
    height: 100%;
    min-height: calc(1.5em * 4);
}

.tiptap-editor .ProseMirror {
    outline: none;
    height: 100%;
    min-height: calc(1.5em * 4);
}

.tiptap-toolbar {
    border-top-left-radius: 0.25rem;
    border-top-right-radius: 0.25rem;
}

.is-invalid .tiptap-editor {
    border-color: transparent;
}
</style>
