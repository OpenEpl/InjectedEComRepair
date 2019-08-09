using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Linq;
using QIQI.EProjectFile;
using QIQI.EProjectFile.Expressions;
using QIQI.EProjectFile.Statements;

namespace InjectedEComRepair
{
    public partial class Form1 : Form
    {

        public Form1()
        {
            InitializeComponent();
        }

        private static string InputPassword(string tip)
        {
            var passwordDialog = new InputPasswordDialog();
            string password = null;
            passwordDialog.TipTextBox.Text = tip;
            if (passwordDialog.ShowDialog() == DialogResult.OK)
            {
                password = passwordDialog.PasswordTextBox.Text;
            }
            passwordDialog.Dispose();
            return password;
        }

#pragma warning disable CS0164
        private void Form1_Load(object sender, EventArgs e)
        {
            https://qiqiworld.tk/ 作者个人主页
            var guiVersionInfo = Attribute.GetCustomAttribute(typeof(Program).Assembly, typeof(System.Reflection.AssemblyInformationalVersionAttribute))
                as System.Reflection.AssemblyInformationalVersionAttribute;
            var coreVersionInfo = Attribute.GetCustomAttribute(typeof(EProjectFile).Assembly, typeof(System.Reflection.AssemblyInformationalVersionAttribute))
                as System.Reflection.AssemblyInformationalVersionAttribute;
            this.Text = string.Format("易模块手工分析型病毒查杀工具 v{0} (Core: v{1})", guiVersionInfo?.InformationalVersion ?? "Unknown", coreVersionInfo?.InformationalVersion ?? "Unknown");
        }
#pragma warning restore CS0164

        private void DebugButton_Click(object sender, EventArgs e)
        {
            bool outputSessionData = checkBox1.Checked;
            bool parseCodeData = checkBox2.Checked;
            bool outputTextCode = checkBox3.Checked;
            string fileName = textBox2.Text;
            textBox1.Text = "正在处理...";

            new Task(() =>
            {
                try
                {
                    CodeSectionInfo codeSectionInfo = null;
                    ResourceSectionInfo resourceSectionInfo = null;
                    LosableSectionInfo losableSectionInfo = null;
                    Encoding encoding = Encoding.GetEncoding("gbk");
                    var output = new StringBuilder();
                    using (var projectFileReader = new ProjectFileReader(File.OpenRead(fileName), InputPassword))
                    {
                        while (!projectFileReader.IsFinish)
                        {
                            var section = projectFileReader.ReadSection();
                            if (outputSessionData)
                            {
                                output.AppendLine("---------------" + section.Name + "---------------");
                                output.AppendLine("CanSkip: " + section.CanSkip.ToString());
                                output.AppendLine("Key: 0x" + section.Key.ToString("X8"));
                                output.Append("Data: ");
                            }
                            switch (section.Key)
                            {
                                case ESystemInfo.SectionKey:
                                    {
                                        var systemInfo = ESystemInfo.Parse(section.Data);
                                        encoding = systemInfo.Encoding;
                                        if (outputSessionData) output.AppendLine(systemInfo.ToString());
                                    }
                                    break;
                                case ProjectConfigInfo.SectionKey:
                                    {
                                        var projectConfig = ProjectConfigInfo.Parse(section.Data, encoding);
                                        if (outputSessionData) output.AppendLine(projectConfig.ToString());
                                    }
                                    break;
                                case CodeSectionInfo.SectionKey:
                                    codeSectionInfo = CodeSectionInfo.Parse(section.Data, encoding, projectFileReader.CryptEc);
                                    if (outputSessionData) output.AppendLine(codeSectionInfo.ToString());
                                    break;
                                case EPackageInfo.SectionKey:
                                    {
                                        var packageInfo = EPackageInfo.Parse(section.Data, encoding);
                                        if (outputSessionData) output.AppendLine(packageInfo.ToString());
                                    }
                                    break;
                                case ResourceSectionInfo.SectionKey:
                                    resourceSectionInfo = ResourceSectionInfo.Parse(section.Data, encoding);
                                    if (outputSessionData) output.AppendLine(resourceSectionInfo.ToString());
                                    break;

                                case InitEcSectionInfo.SectionKey:
                                    {
                                        var initEcSectionInfo = InitEcSectionInfo.Parse(section.Data, encoding);
                                        if (outputSessionData) output.AppendLine(initEcSectionInfo.ToString());
                                    }
                                    break;
                                case LosableSectionInfo.SectionKey:
                                    {
                                        losableSectionInfo = LosableSectionInfo.Parse(section.Data, encoding);
                                        if (outputSessionData) output.AppendLine(losableSectionInfo.ToString());
                                    }
                                    break;
                                case FolderSectionInfo.SectionKey:
                                    {
                                        var folderSectionInfo = FolderSectionInfo.Parse(section.Data, encoding);
                                        if (outputSessionData) output.AppendLine(folderSectionInfo.ToString());
                                    }
                                    break;
                                default:
                                    if (outputSessionData)
                                    {
                                        output.AppendLine("{");
                                        output.Append("  \"Unknown\": \"");
                                        output.Append(section.Data.ToHexString());
                                        output.AppendLine("\"");
                                        output.AppendLine("}");
                                    }
                                    break;
                            }
                        }
                        if (parseCodeData)
                        {
                            output.AppendLine("<<<<<<<<<<<<<<<ParseTest>>>>>>>>>>>>>>>");
                            foreach (var method in codeSectionInfo.Methods)
                            {
                                output.AppendLine($"###Method: {(string.IsNullOrEmpty(method.Name) ? "Unknown" : method.Name)}{$"Id: {method.Id})###"}");
                                try
                                {
#pragma warning disable CS0612 // 类型或成员已过时
                                    var block = CodeDataParser.ParseStatementBlock(method.CodeData.ExpressionData, encoding, out var lineOffest, out var blockOffest);
#pragma warning restore CS0612 // 类型或成员已过时
                                    var GenCodeData = block.ToCodeData(encoding);
                                    output.Append("Raw: ");
                                    output.AppendLine(method.CodeData.ToString());
                                    output.Append("FullRewrite: ");
                                    output.AppendLine(GenCodeData.ToString());
                                    output.Append("OldOffestRepairer: ");
                                    output.AppendLine("{");
                                    output.AppendLine("  \"LineOffest\": \"" + lineOffest.ToHexString() + "\"");
                                    output.AppendLine("  \"BlockOffest\": \"" + blockOffest.ToHexString() + "\"");
                                    output.AppendLine("}");
                                }
                                catch (Exception exception)
                                {
                                    output.AppendLine("出现错误：");
                                    output.AppendLine(exception.ToString());
                                    output.AppendLine();
                                }
                            }
                        }
                        if(outputTextCode)
                        {
                            output.AppendLine("<<<<<<<<<<<<<<<TextCode>>>>>>>>>>>>>>>");
                            var nameMap = new IdToNameMap(codeSectionInfo, resourceSectionInfo, losableSectionInfo);
                            output.AppendLine(".版本 2");
                            output.AppendLine();
                            output.AppendLine(codeSectionInfo.ToTextCode(nameMap));
                            output.AppendLine(resourceSectionInfo.ToTextCode(nameMap));
                        }
                    }
                    Invoke(new Action(() =>
                    {
                        textBox1.Text = output.ToString();
                    }));
                }
                catch (Exception exception)
                {
                    Invoke(new Action(() =>
                    {
                        textBox1.Text = $"出现错误：\r\n{exception}\r\n请加群后将文件发送给作者以便修复此问题";
                    }));
                }
            })
            .Start();
        }

        private void SelectFileButton_Click(object sender, EventArgs e)
        {
            if (openFileDialog1.ShowDialog() == DialogResult.OK)
            {
                textBox2.Text = openFileDialog1.FileName;
            }
        }

        private void RepairButton_Click(object sender, EventArgs e)
        {
            string fileName = textBox2.Text;
            string output = textBox3.Text;
            int engine = radioButton1.Checked ? 0 : 1;
            textBox1.Text = "正在处理...";
            new Task(() => 
            {
                try
                {

                    RepairEProjectFile(fileName, output, InputPassword, engine);
                    Invoke(new Action(() =>
                    {
                        textBox1.Text = $"处理完成，修复后的文件：{output}";
                    }));
                }
                catch (Exception exception)
                {
                    Invoke(new Action(() =>
                    {
                        textBox1.Text = $"出现错误：\r\n{exception}\r\n请加群后将文件发送给作者以便修复此问题";
                    }));
                }

            }).Start();
        }

        private static void RepairEProjectFile(string source, string target, ProjectFileReader.OnInputPassword inputPassword = null, int engine = 0)
        {
            var file = new EProjectFile();
            file.Load(File.OpenRead(source), inputPassword);
            var libNameMap = new IdToNameMap(file.Code.Libraries);
            var classIdMap = file.Code.Classes.ToDictionary(x => x.Id);
            var methodIdMap = file.Code.Methods.ToDictionary(x => x.Id);
            file.ESystemInfo.FileType = 1;
            foreach (var classInfo in file.Code.Classes)
            {
                if (!ValidEplName(classInfo.Name))
                {
                    classInfo.Name = ParseDebugComment(classInfo.Comment);
                    if (classInfo.Name == null)
                    {
                        if (classInfo.Comment == "_-@M<>")
                        {
                            classInfo.Comment = "";
                        }
                        classInfo.Name = (classInfo.BaseClass == 0 ? "_程序集" : "_类") + (classInfo.Id & EplSystemId.Mask_Num).ToString("X");
                    }
                    else
                    {
                        classInfo.Comment = "";
                    }
                }
                FixVariablesName(classInfo.Variables, classInfo.BaseClass == 0 ? "_程序集变量" : "_成员");
            }
            FixVariablesName(file.Code.GlobalVariables, "_全局");
            foreach (var method in file.Code.Methods)
            {
                if (!ValidEplName(method.Name))
                {
                    method.Name = ParseDebugComment(method.Comment);
                    if (method.Name == null)
                    {
                        if (method.Comment == "_-@S<>")
                        {
                            method.Comment = "";
                        }
                        method.Name = $"_子程序{(method.Id & EplSystemId.Mask_Num).ToString("X")}";
                    }
                    else
                    {
                        method.Comment = "";
                    }
                }
                FixVariablesName(method.Parameters, "_参数", true);
                FixVariablesName(method.Variables, "_局部", true);

                StatementBlock block = null;
                try
                {
                    var codeData = method.CodeData;
#pragma warning disable CS0612 // 类型或成员已过时
                    block = CodeDataParser.ParseStatementBlock(method.CodeData.ExpressionData, file.Encoding, out codeData.LineOffest, out codeData.BlockOffest);
#pragma warning restore CS0612 // 类型或成员已过时
                    if (engine == 1) 
                    {
                        codeData = block.ToCodeData(file.Encoding);
                    }
                    method.CodeData = codeData;
                }
                catch (Exception exception)
                {
                    method.Comment = $"[**修复失败:{exception.ToString().Replace("\r\n","<NewLine>")}**]{method.Comment}";
                    continue;
                }
            }
            foreach (var structInfo in file.Code.Structs)
            {
                if (!ValidEplName(structInfo.Name))
                {
                    structInfo.Name = $"_结构{(structInfo.Id & EplSystemId.Mask_Num).ToString("X")}";
                }
                FixVariablesName(structInfo.Member, "_成员", false);
            }
            foreach (var dll in file.Code.DllDeclares)
            {
                if (!ValidEplName(dll.Name))
                {
                    dll.Name = dll.EntryPoint;
                    if (dll.Name.StartsWith("@"))
                    {
                        dll.Name = dll.Name.Substring(1);
                    }
                    dll.Name = "_" + dll.Name;
                    if (!ValidEplName("_" + dll.Name))
                    {
                        dll.Name = "";
                    }
                    dll.Name = $"_DLL命令{(dll.Id & EplSystemId.Mask_Num).ToString("X")}{dll.Name}";
                }
                FixVariablesName(dll.Parameters, "_参数", true);
            }
            foreach (var constant in file.Resource.Constants)
            {
                if (!ValidEplName(constant.Name))
                {
                    constant.Name = constant.Value == null ? "" : $"_常量{(constant.Id & EplSystemId.Mask_Num).ToString("X")}";
                }
            }
            foreach (var formInfo in file.Resource.Forms)
            {
                if (!ValidEplName(formInfo.Name))
                {
                    formInfo.Name = $"_窗口{(formInfo.Id & EplSystemId.Mask_Num).ToString("X")}";
                }
                foreach (var elem in formInfo.Elements)
                {
                    if (elem is FormMenuInfo menu)
                    {
                        MethodInfo eventMethod = null;
                        if (menu.ClickEvent != 0)
                        {
                            methodIdMap.TryGetValue(menu.ClickEvent, out eventMethod);
                        }
                        if (string.IsNullOrEmpty(menu.Name))
                        {
                            if (ValidEplName("_" + menu.Text))
                            {
                                menu.Name = $"_菜单{(menu.Id & EplSystemId.Mask_Num).ToString("X")}_{menu.Text}";
                            }
                            else
                            {
                                menu.Name = $"_菜单{(menu.Id & EplSystemId.Mask_Num).ToString("X")}";
                            }
                            if (eventMethod != null && eventMethod.Name != null && eventMethod.Name.StartsWith("_") && eventMethod.Name.EndsWith("_被选择"))//尝试从事件子程序名还原名称
                            {
                                menu.Name = eventMethod.Name.Substring(1, eventMethod.Name.Length - 5);
                            }
                        }
                        if (eventMethod != null)
                        {
                            eventMethod.Name = $"_{menu.Name}_被选择";
                        }
                    }
                    else if (elem is FormControlInfo control)
                    {
                        var elemName = control.Name;

                        if (!ValidEplName(elemName))
                        {
                            if (control.Events.Length > 0)//尝试从子程序名恢复窗口名
                            {
                                var eventItem = control.Events[0];
                                if (methodIdMap.TryGetValue(eventItem.Value, out var eventMethod))
                                {
                                    var eventName = libNameMap.GetLibTypeName(control.DataType, eventItem.Key);
                                    if (eventMethod.Name.StartsWith("_") && eventMethod.Name.EndsWith($"_{eventName}"))
                                    {
                                        formInfo.Name = eventMethod.Name.Substring(1, eventMethod.Name.Length - 1 - eventName.Length - 1);
                                    }
                                }
                            }
                            elemName = formInfo.Name;
                        }
                        foreach (var eventItem in control.Events)
                        {
                            if (methodIdMap.TryGetValue(eventItem.Value, out var eventMethod))
                            {
                                var eventName = libNameMap.GetLibTypeName(control.DataType, eventItem.Key);
                                eventMethod.Name = $"_{elemName}_{eventName}";
                            }
                        }
                    }
                }
                if (classIdMap.TryGetValue(formInfo.Class, out var formClass))
                {
                    var prefix = $"[“{formInfo.Name}”的窗口程序集]";
                    if (!formClass.Comment.StartsWith(prefix))
                    {
                        formClass.Comment = $"{prefix}{formClass.Comment}";
                    }
                }
            }
            {
                var newInitMethod = new List<int>(file.InitEcSectionInfo.InitMethod.Length);
                var newEcName = new List<string>(file.InitEcSectionInfo.InitMethod.Length);
                for (int i = 0; i < file.InitEcSectionInfo.InitMethod.Length; i++)
                {
                    if (!methodIdMap.TryGetValue(file.InitEcSectionInfo.InitMethod[i], out var initMethod))
                    {
                        continue;
                    }
                    initMethod.Name = $"初始模块_{i + 1}";
                    if (ValidEplName("_" + file.InitEcSectionInfo.EcName[i]))
                    {
                        initMethod.Name += "_" + file.InitEcSectionInfo.EcName[i];
                    }

                    var prefix = $"[禁止删除][注意：本子程序将自动在启动时被调用，且早于 _启动子程序 被调用][为内联的模块“{file.InitEcSectionInfo.EcName[i]}”做初始化工作]";
                    if (!initMethod.Comment.StartsWith(prefix))
                    {
                        initMethod.Comment = $"{prefix}{initMethod.Comment}";
                    }

                    newInitMethod.Add(file.InitEcSectionInfo.InitMethod[i]);
                    newEcName.Add(i < file.InitEcSectionInfo.EcName.Length ? file.InitEcSectionInfo.EcName[i] : "");
                }
                file.InitEcSectionInfo.InitMethod = newInitMethod.ToArray();
                file.InitEcSectionInfo.EcName = newEcName.ToArray();
            }
            {
                if (methodIdMap.TryGetValue(file.Code.MainMethod, out var mainMethod))
                {
                    mainMethod.Name = "_启动子程序";
                    if (file.InitEcSectionInfo.InitMethod.Length > 0)
                    {
                        var prefix = "[注意：本子程序将在 初始模块_X 后调用]";
                        if (!mainMethod.Comment.StartsWith(prefix))
                        {
                            mainMethod.Comment = $"{prefix}{mainMethod.Comment}";
                        }
                    }
                }
            }
            file.Save(File.Create(target));
        }
        private static void FixVariablesName(AbstractVariableInfo[] variables, string prefix, bool useIndexInsteadOfId = false)
        {
            int i = 1;
            foreach (var variable in variables)
            {
                if (string.IsNullOrEmpty(variable.Name))
                {
                    variable.Name = prefix + (useIndexInsteadOfId ? i.ToString() : (variable.Id & EplSystemId.Mask_Num).ToString("X"));
                }
                i++;
            }
        }

        private static Regex validEplNameRegex = new Regex(@"^[_A-Za-z\u0080-\uFFFF][_0-9A-Za-z\u0080-\uFFFF]*$", RegexOptions.Compiled);
        private static bool ValidEplName(string name)
        {
            return validEplNameRegex.IsMatch(name);
        }
        private static Regex debugCommentMatchRegex = new Regex(@"^_-@[MS]<([_A-Za-z\u0080-\uFFFF][_0-9A-Za-z\u0080-\uFFFF]*)>$", RegexOptions.Compiled);
        private static string ParseDebugComment(string comment)
        {
            var matchItem = debugCommentMatchRegex.Match(comment);
            if (matchItem == null || !matchItem.Success)
            {
                return null;
            }
            return matchItem.Groups[1].Value;
        }

        private void Form1_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                e.Effect = DragDropEffects.Link;
            }
            else
            {
                e.Effect = DragDropEffects.None;
            }
        }

        private void Form1_DragDrop(object sender, DragEventArgs e)
        {
            string filePath = ((Array)e.Data.GetData(DataFormats.FileDrop)).GetValue(0).ToString();
            textBox2.Text = filePath;
        }

        private void Form1_Activated(object sender, EventArgs e)
        {
            label2.Text = Encoding.UTF8.GetString(new byte[]
            {
                0x41, 0x44, 0xEF, 0xBC, 0x9A, 0xE3, 0x80, 0x90, 0xE6, 0x9C, 0xAC, 0xE5, 0xB7, 0xA5, 0xE5, 0x85,
                0xB7, 0xE5, 0xAE, 0x98, 0xE6, 0x96, 0xB9, 0xE3, 0x80, 0x91, 0xE6, 0x98, 0x93, 0xE8, 0xAF, 0xAD,
                0xE8, 0xA8, 0x80, 0xE9, 0xAB, 0x98, 0xE7, 0xBA, 0xA7, 0xE7, 0xBC, 0x96, 0xE7, 0xA8, 0x8B, 0x51,
                0x51, 0xE7, 0xBE, 0xA4, 0x36, 0x30, 0x35, 0x33, 0x31, 0x30, 0x39, 0x33, 0x33, 0xEF, 0xBC, 0x8C,
                0xE6, 0xAC, 0xA2, 0xE8, 0xBF, 0x8E, 0xE5, 0x8A, 0xA0, 0xE5, 0x85, 0xA5
            });
        }
    }
    public static class HexUtil
    {
        public static string ToHexString(this byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            if (bytes != null)
            {
                for (int i = 0; i < bytes.Length; i++)
                {
                    sb.Append(bytes[i].ToString("X2"));
                }
            }
            return sb.ToString();
        }
    }
}
