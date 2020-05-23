using QIQI.EProjectFile;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace InjectedEComRepair
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            this.OutputTextBox.Text = Properties.Resources.WelcomeText;
            var guiVersionInfo = Attribute.GetCustomAttribute(typeof(MainWindow).Assembly, typeof(System.Reflection.AssemblyInformationalVersionAttribute))
                as System.Reflection.AssemblyInformationalVersionAttribute;
            var coreVersionInfo = Attribute.GetCustomAttribute(typeof(EProjectFile).Assembly, typeof(System.Reflection.AssemblyInformationalVersionAttribute))
                as System.Reflection.AssemblyInformationalVersionAttribute;
            this.Title = string.Format("易模块手工分析型病毒查杀工具 v{0} (Core: v{1})", guiVersionInfo?.InformationalVersion ?? "Unknown", coreVersionInfo?.InformationalVersion ?? "Unknown");
        }

        private void SelectFileButton_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog()
            {
                Filter = "EPL files|*.e;*.ec|All files|*"
            };
            if (dialog.ShowDialog().GetValueOrDefault())
            {
                InputFileTextBox.Text = dialog.FileName;
            }
        }

        private void DebugButton_Click(object sender, RoutedEventArgs e)
        {
            bool outputSessionData = OutputSessionDataCheckBox.IsChecked.GetValueOrDefault();
            bool parseCodeData = ParseCodeDataCheckBox.IsChecked.GetValueOrDefault();
            bool outputTextCode = OutputTextCodeCheckBox.IsChecked.GetValueOrDefault();
            string fileName = InputFileTextBox.Text;
            OutputTextBox.Text = "正在处理...";

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
#pragma warning disable CA1031 // Do not catch general exception types
                                catch (Exception exception)
                                {
                                    output.AppendLine("出现错误：");
                                    output.AppendLine(exception.ToString());
                                    output.AppendLine();
                                }
#pragma warning restore CA1031 // Do not catch general exception types
                            }
                        }
                        if (outputTextCode)
                        {
                            output.AppendLine("<<<<<<<<<<<<<<<TextCode>>>>>>>>>>>>>>>");
                            var nameMap = new IdToNameMap(codeSectionInfo, resourceSectionInfo, losableSectionInfo);
                            output.AppendLine(".版本 2");
                            output.AppendLine();
                            output.AppendLine(codeSectionInfo.ToTextCode(nameMap));
                            output.AppendLine(resourceSectionInfo.ToTextCode(nameMap));
                        }
                    }
                    Dispatcher.Invoke(new Action(() =>
                    {
                        OutputTextBox.Text = output.ToString();
                    }));
                }
#pragma warning disable CA1031 // Do not catch general exception types
                catch (Exception exception)
                {
                    Dispatcher.Invoke(new Action(() =>
                    {
                        OutputTextBox.Text = $"出现错误：\r\n{exception}\r\n请加群后将文件发送给作者以便修复此问题";
                    }));
                }
#pragma warning restore CA1031 // Do not catch general exception types
            })
            .Start();
        }

        private void RepairButton_Click(object sender, RoutedEventArgs e)
        {

            string fileName = InputFileTextBox.Text;
            string output = OutputFileTextBox.Text;
            int engine = FixOffestRadioButton.IsChecked.GetValueOrDefault() ? 0 : 1;
            OutputTextBox.Text = "正在处理...";
            new Task(() =>
            {
                try
                {
                    EProjectRepair.RepairEProjectFile(File.OpenRead(fileName), File.Create(output), InputPassword, engine);
                    Dispatcher.Invoke(new Action(() =>
                    {
                        OutputTextBox.Text = $"处理完成，修复后的文件：{output}";
                    }));
                }
#pragma warning disable CA1031 // Do not catch general exception types
                catch (Exception exception)
                {
                    Dispatcher.Invoke(new Action(() =>
                    {
                        OutputTextBox.Text = $"出现错误：\r\n{exception}\r\n请加群后将文件发送给作者以便修复此问题";
                    }));
                }
#pragma warning restore CA1031 // Do not catch general exception types

            }).Start();
        }

        private static string InputPassword(string tip)
        {
            return null;
        }
    }
}
